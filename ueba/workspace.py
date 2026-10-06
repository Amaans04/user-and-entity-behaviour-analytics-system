"""Workspaces: independent datasets, each with its own logs, profiles, alerts and models.

    data/                        <- the built-in "Demo" workspace (synthetic company)
      raw/  ueba.db  models.joblib
    data/workspaces/<slug>/      <- one folder per monitored environment
      workspace.json             name, settings, upload history, saved column mappings
      raw/<stream>.csv           everything collected so far, in the canonical schema
      inbox/                     drop zone: files here are imported automatically by the service
        processed/  failed/      (failed files get a <name>.error.txt explaining why)
      ueba.db  models.joblib  reports/

Data arrives by upload (dashboard), by dropping files into ``inbox/``, or through the
ingest API (agents). It is *appended* to a stream with de-duplication, like a SIEM
collecting day after day.

Analysis is incremental: the models are trained once the learning period is covered;
after that only the days touched by new data are scored (``update``). A full re-train
(``analyse``) happens when settings, the user directory or the asset inventory change.

Every change to a workspace runs under a process-wide file lock, because the dashboard
and the background service may work on the same workspace at the same time.
"""
from __future__ import annotations

import contextlib
import copy
import json
import re
import shutil
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import pandas as pd

from .config import CONFIG, DATA_DIR, DB_PATH, REPORTS_DIR
from .sources import LOG_STREAMS, SCHEMA

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows: in-process locking only
    fcntl = None

WS_ROOT = DATA_DIR / "workspaces"
DEMO = "demo"
MIN_LEARNING_DAYS = 7
INBOX_SETTLE_SECONDS = 2.0       # ignore files still being written
DEFAULT_SETTINGS = dict(auto_ingest=True, notify_webhook="", notify_email="", notify_min_severity="high")


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _slug(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:40] or "workspace"
    return "ws-demo" if s == DEMO else s


# ----------------------------------------------------------------- locking
_tls = threading.local()
_thread_locks: dict[str, threading.RLock] = {}
_registry_lock = threading.Lock()


@contextlib.contextmanager
def _locked(path: Path):
    """Re-entrant exclusive lock: a thread lock (same process) + an flock (other processes)."""
    key = str(path)
    with _registry_lock:
        tlock = _thread_locks.setdefault(key, threading.RLock())
    held = getattr(_tls, "held", None)
    if held is None:
        held = _tls.held = {}
    with tlock:
        if held.get(key):
            held[key] += 1
            try:
                yield
            finally:
                held[key] -= 1
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a+") as fh:
            if fcntl:
                fcntl.flock(fh, fcntl.LOCK_EX)
            held[key] = 1
            try:
                yield
            finally:
                held[key] = 0
                if fcntl:
                    fcntl.flock(fh, fcntl.LOCK_UN)


@dataclass
class Workspace:
    slug: str
    root: Path
    meta: dict

    # ------------------------------------------------------------- paths
    @property
    def is_demo(self) -> bool:
        return self.slug == DEMO

    @property
    def name(self) -> str:
        return self.meta.get("name", self.slug)

    @property
    def raw_dir(self) -> Path:
        return self.root / "raw"

    @property
    def inbox(self) -> Path:
        return self.root / "inbox"

    @property
    def db_path(self) -> Path:
        return DB_PATH if self.is_demo else self.root / "ueba.db"

    @property
    def reports_dir(self) -> Path:
        return REPORTS_DIR if self.is_demo else self.root / "reports"

    @property
    def alert_threshold(self) -> float:
        return float(self.meta.get("alert_threshold", CONFIG.alert_threshold))

    @property
    def learning_days(self) -> int:
        return int(self.meta.get("learning_days", CONFIG.train_days))

    def setting(self, key: str):
        return self.meta.get("settings", {}).get(key, DEFAULT_SETTINGS.get(key))

    # ------------------------------------------------------------- state
    def lock(self):
        return _locked(self.root / ".lock")

    def reload(self) -> "Workspace":
        if not self.is_demo:
            f = self.root / "workspace.json"
            if f.exists():
                self.meta = json.loads(f.read_text())
        return self

    def save(self):
        if self.is_demo:
            return
        self.root.mkdir(parents=True, exist_ok=True)
        tmp = self.root / "workspace.json.tmp"
        tmp.write_text(json.dumps(self.meta, indent=2, default=str))
        tmp.replace(self.root / "workspace.json")      # atomic: readers never see half a file

    @contextlib.contextmanager
    def mutate(self):
        """Lock, re-read the latest metadata, let the caller change it, save."""
        with self.lock():
            self.reload()
            yield self.meta
            self.save()

    def stream_path(self, stream: str) -> Path:
        return self.raw_dir / f"{stream}.csv"

    def streams(self) -> dict[str, dict]:
        """Per-stream summary: rows, first/last timestamp, number of days."""
        out = {}
        for stream in SCHEMA:
            p = self.stream_path(stream)
            if not p.exists():
                continue
            info = self.meta.get("streams", {}).get(stream)
            if info is None:    # demo / legacy folder - summarise from the file
                cols = ["timestamp"] if stream in LOG_STREAMS else None
                df = pd.read_csv(p, usecols=cols)
                info = dict(rows=len(df))
                if cols:
                    ts = pd.to_datetime(df["timestamp"], errors="coerce").dropna()
                    info.update(first=str(ts.min()), last=str(ts.max()), days=int(ts.dt.normalize().nunique()))
            out[stream] = info
        return out

    def coverage(self) -> dict:
        """First/last day across all log streams and how many days that spans."""
        s = [v for k, v in self.streams().items() if k in LOG_STREAMS and v.get("rows")]
        if not s:
            return dict(first=None, last=None, days=0)
        first = min(pd.Timestamp(v["first"]) for v in s).normalize()
        last = max(pd.Timestamp(v["last"]) for v in s).normalize()
        return dict(first=str(first.date()), last=str(last.date()), days=(last - first).days + 1)

    def status(self) -> dict:
        """Lifecycle: empty -> needs_analysis -> learning -> monitoring."""
        cov = self.coverage()
        analysed = self.db_path.exists()
        st = dict(coverage=cov, learning_days=self.learning_days, analysed=analysed,
                  last_analysis=self.meta.get("last_analysis"), dirty=bool(self.meta.get("dirty")),
                  inbox=self.inbox_count())
        if not cov["days"]:
            st["state"] = "empty"
        elif not analysed or st["dirty"]:
            st["state"] = "needs_analysis"
        elif cov["days"] <= self.learning_days:
            st["state"] = "learning"
        else:
            st["state"] = "monitoring"
        return st

    # ------------------------------------------------------------- data in
    def add(self, stream: str, df: pd.DataFrame, filename: str, mapping: dict, signature: str,
            source: str = "upload") -> dict:
        """Append converted rows to a stream; returns rows added (after de-duplication)."""
        if self.is_demo:
            raise ValueError("The demo workspace is read-only - create a workspace to upload your own logs")
        with self.mutate() as meta:
            self.raw_dir.mkdir(parents=True, exist_ok=True)
            p = self.stream_path(stream)
            cols = list(SCHEMA[stream])
            new = df[cols].copy()
            if "timestamp" in new:
                new["timestamp"] = pd.to_datetime(new["timestamp"]).dt.strftime("%Y-%m-%d %H:%M:%S")
            old = pd.read_csv(p, dtype=str, keep_default_na=False) if p.exists() else None
            if old is not None:
                before = len(old)
                merged = pd.concat([old, new.astype(str).replace({"nan": ""})], ignore_index=True)
                key = ["user"] if stream == "users" else ["device"] if stream == "devices" else None
                merged = merged.drop_duplicates(subset=key, keep="last") if key else merged.drop_duplicates()
            else:
                before = 0
                merged = new
            if "timestamp" in merged:
                merged = merged.sort_values("timestamp", kind="stable")
            tmp = p.with_suffix(".csv.tmp")
            merged.to_csv(tmp, index=False)
            tmp.replace(p)
            added = len(merged) - before

            info = dict(rows=len(merged), updated=_now())
            if "timestamp" in merged:
                ts = pd.to_datetime(merged["timestamp"], errors="coerce").dropna()
                info.update(first=str(ts.min()), last=str(ts.max()), days=int(ts.dt.normalize().nunique()))
                if added and len(new):
                    first_new = str(pd.to_datetime(new["timestamp"]).min().date())
                    meta["pending_from"] = min(meta.get("pending_from") or first_new, first_new)
            elif added and stream in ("users", "devices"):
                meta["needs_full"] = True          # peer groups / inventory changed -> retrain
            meta.setdefault("streams", {})[stream] = info
            meta.setdefault("uploads", []).append(dict(
                file=filename, stream=stream, rows=len(new), added=int(added), source=source, at=_now()))
            meta["uploads"] = meta["uploads"][-500:]
            meta.setdefault("mappings", {})[signature] = dict(stream=stream, mapping=mapping)
            if added:
                meta["dirty"] = True
        return dict(rows=len(new), added=int(added), total=len(merged))

    def import_folder(self, src: Path, source: str = "folder") -> dict:
        """Replace this workspace's logs with a folder already in the canonical schema (e.g. the
        CERT adapter's output) - a bulk load that skips per-row mapping."""
        if self.is_demo:
            raise ValueError("The demo workspace is read-only")
        with self.mutate() as meta:
            self.raw_dir.mkdir(parents=True, exist_ok=True)
            meta["streams"] = {}
            for stream in SCHEMA:
                f = Path(src) / f"{stream}.csv"
                if not f.exists():
                    continue
                shutil.copyfile(f, self.stream_path(stream))
                cols = ["timestamp"] if stream in LOG_STREAMS else None
                df = pd.read_csv(f, usecols=cols)
                info = dict(rows=len(df), updated=_now())
                if cols and len(df):
                    ts = pd.to_datetime(df["timestamp"], errors="coerce").dropna()
                    info.update(first=str(ts.min()), last=str(ts.max()), days=int(ts.dt.normalize().nunique()))
                meta["streams"][stream] = info
            meta.setdefault("uploads", []).append(dict(file=str(src), stream="*", source=source, at=_now()))
            meta["dirty"] = meta["needs_full"] = True
        return meta["streams"]

    def clear_stream(self, stream: str):
        if self.is_demo:
            raise ValueError("The demo workspace is read-only")
        with self.mutate() as meta:
            self.stream_path(stream).unlink(missing_ok=True)
            meta.get("streams", {}).pop(stream, None)
            meta["dirty"] = meta["needs_full"] = True

    def changed_from(self, date: str):
        """Something affecting ``date`` and later changed (e.g. an analyst verdict alters what
        the baseline learns) - re-score from there on the next update."""
        if self.is_demo:
            return
        with self.mutate() as meta:
            meta["pending_from"] = min(meta.get("pending_from") or str(date), str(date))
            meta["dirty"] = True

    def saved_mapping(self, signature: str) -> dict | None:
        return self.meta.get("mappings", {}).get(signature)

    def set_learning_days(self, days: int):
        with self.mutate() as meta:
            meta["learning_days"] = int(days)
            meta["dirty"] = meta["needs_full"] = True

    def set_alert_threshold(self, value: float):
        """Daily risk needed to raise an alert. Only alerting changes, so the next update re-generates
        alerts with the saved models - no re-training."""
        if not 10 <= float(value) <= 95:
            raise ValueError("The alert threshold must be between 10 and 95")
        with self.mutate() as meta:
            meta["alert_threshold"] = float(value)
            meta["dirty"] = True

    def update_settings(self, **kw):
        with self.mutate() as meta:
            meta.setdefault("settings", {}).update(kw)

    # ------------------------------------------------------------- inbox
    def inbox_files(self) -> list[Path]:
        if not self.inbox.exists():
            return []
        now = time.time()
        return sorted(p for p in self.inbox.iterdir()
                      if p.is_file() and not p.name.startswith(".") and not p.name.endswith((".part", ".tmp"))
                      and now - p.stat().st_mtime >= INBOX_SETTLE_SECONDS)

    def inbox_count(self) -> int:
        return len(self.inbox_files()) if not self.is_demo else 0

    def process_inbox(self) -> list[dict]:
        """Import every settled file in ``inbox/``. A file named ``<stream>__anything.ext``
        is forced to that stream; otherwise the saved mapping for the same columns is used,
        or the stream and columns are guessed. Bad files go to ``inbox/failed/`` with a reason."""
        from .sources import convert, guess_mapping, guess_stream, mapping_signature, read_bytes
        results = []
        for p in self.inbox_files():
            done = self.inbox / "processed"
            try:
                parsed = read_bytes(p.name, p.read_bytes())
                if not parsed:
                    raise ValueError("no readable CSV / JSON content")
                staged = []
                for fname, raw in parsed:
                    cols = [str(c) for c in raw.columns]
                    raw.columns = cols
                    sig = mapping_signature(cols)
                    forced = p.name.split("__", 1)[0] if "__" in p.name else None
                    saved = self.saved_mapping(sig)
                    if forced and forced not in SCHEMA:
                        raise ValueError(f"unknown stream prefix '{forced}'")
                    stream = forced or (saved["stream"] if saved else guess_stream(cols, fname))
                    mapping = saved["mapping"] if saved and saved["stream"] == stream else guess_mapping(stream, cols)
                    conv = convert(stream, raw, mapping)
                    if not conv.ok:
                        raise ValueError(f"{fname} as {stream}: " + "; ".join(conv.errors or ["no usable rows"]))
                    staged.append((fname, stream, conv, mapping, sig))
                added = [dict(file=f, stream=s, **self.add(s, c.df, f, m, g, source="inbox"))
                         for f, s, c, m, g in staged]
                results.append(dict(file=p.name, ok=True, imported=added))
            except Exception as e:  # noqa: BLE001 - one bad file must not stop the others
                done = self.inbox / "failed"
                done.mkdir(parents=True, exist_ok=True)
                (done / f"{p.name}.error.txt").write_text(f"{_now()}  {type(e).__name__}: {e}\n")
                results.append(dict(file=p.name, ok=False, error=str(e)))
            done.mkdir(parents=True, exist_ok=True)
            target = done / p.name
            if target.exists():
                target = done / f"{p.stem}-{int(time.time() * 1000)}{p.suffix}"
            p.replace(target)
        return results

    # ------------------------------------------------------------- analysis
    def config(self):
        cfg = copy.deepcopy(CONFIG)
        if not self.is_demo:
            cfg.alert_threshold = self.alert_threshold
            cfg.train_days = self.learning_days
            cfg.warmup_days = min(CONFIG.warmup_days, max(1, self.learning_days // 6))
        return cfg

    def _run(self, mode: str) -> dict:
        from .pipeline import run
        if self.is_demo:
            return run(self.raw_dir, self.db_path, CONFIG, mode=mode)
        if not any(self.stream_path(s).exists() for s in LOG_STREAMS):
            raise ValueError("Upload at least one log stream (authentication, access, network or resource)")
        with self.lock():
            self.reload()
            pending = self.meta.get("pending_from")
            if self.meta.get("needs_full"):
                mode = "full"
            res = run(self.raw_dir, self.db_path, self.config(), reports_dir=self.reports_dir,
                      mode=mode, rescore_from=pending)
            with self.mutate() as meta:
                meta["dirty"] = meta["needs_full"] = False
                meta.pop("pending_from", None)
                meta["last_analysis"] = _now()
                meta["last_mode"] = res.get("mode", mode)
        return res

    def analyse(self) -> dict:
        """Full re-train + re-score of all history."""
        return self._run("full")

    def update(self) -> dict:
        """Incremental: reuse the trained models and score only what changed."""
        return self._run("update")

    def regenerate_demo(self, seed: int | None = None) -> dict:
        from .generator import generate_dataset
        from .pipeline import run
        if not self.is_demo:
            raise ValueError("Only the demo workspace can be regenerated")
        cfg = copy.deepcopy(CONFIG)
        if seed is not None:
            cfg.seed = seed
        generate_dataset(self.raw_dir, cfg)
        return run(self.raw_dir, self.db_path, cfg)


# ----------------------------------------------------------------- registry
def demo() -> Workspace:
    return Workspace(DEMO, DATA_DIR, dict(name="Demo (synthetic company)", kind="demo"))


def get(slug: str) -> Workspace:
    if slug == DEMO:
        return demo()
    root = WS_ROOT / slug
    f = root / "workspace.json"
    if not f.exists():
        raise KeyError(slug)
    return Workspace(slug, root, json.loads(f.read_text()))


def list_all() -> list[Workspace]:
    out = [demo()]
    if WS_ROOT.exists():
        for f in sorted(WS_ROOT.glob("*/workspace.json")):
            try:
                out.append(get(f.parent.name))
            except (KeyError, json.JSONDecodeError):
                continue
    return out


def find(name_or_slug: str) -> Workspace:
    for ws in list_all():
        if name_or_slug in (ws.slug, ws.name) or _slug(name_or_slug) == ws.slug:
            return ws
    raise KeyError(f"No workspace called '{name_or_slug}'")


def create(name: str, learning_days: int = CONFIG.train_days) -> Workspace:
    name = name.strip()
    if not name:
        raise ValueError("Give the workspace a name")
    with _locked(WS_ROOT / ".registry.lock"):
        base = _slug(name)
        slug, i = base, 2
        while (WS_ROOT / slug).exists():
            slug, i = f"{base}-{i}", i + 1
        ws = Workspace(slug, WS_ROOT / slug, dict(name=name, kind="upload", created=_now(),
                                                  learning_days=int(learning_days), streams={}, uploads=[],
                                                  mappings={}, settings=dict(DEFAULT_SETTINGS), dirty=False))
        ws.raw_dir.mkdir(parents=True, exist_ok=True)
        ws.inbox.mkdir(parents=True, exist_ok=True)
        ws.save()
    return ws


def delete(slug: str):
    if slug == DEMO:
        raise ValueError("The demo workspace cannot be deleted")
    root = WS_ROOT / slug
    with _locked(root / ".lock"):
        shutil.rmtree(root, ignore_errors=True)


def db_meta(db_path: Path) -> dict:
    if not Path(db_path).exists():
        return {}
    with sqlite3.connect(db_path) as con:
        try:
            return dict(con.execute("SELECT key, value FROM meta").fetchall())
        except sqlite3.OperationalError:
            return {}
