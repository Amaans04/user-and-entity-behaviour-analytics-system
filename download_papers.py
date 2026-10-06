"""Download the literature-review papers into ./papers

Run from the project folder (with the virtual environment active):

    python download_papers.py

Free papers are downloaded automatically. Paywalled IEEE papers (and any download
that fails) are listed at the end with a link to open in your browser - log in
through the university's IEEE Xplore access to get those.
"""
import ssl
import sys
import time
import urllib.request
from pathlib import Path

OUT = Path(__file__).resolve().parent / "papers"

# (file name, direct PDF URL or None if paywalled, page to open manually)
PAPERS = [
    ("01_Landauer_2022_UEBA_log_dataset_cloud.pdf",
     "https://www.skopik.at/ait/2022_bigdata.pdf",
     "https://doi.org/10.1109/BigData55660.2022.10020672"),
    ("02_Cui_2022_multi-homed_UEBA_fuzzy_PSO.pdf",
     "https://www.nature.com/articles/s41598-022-26142-w.pdf",
     "https://www.nature.com/articles/s41598-022-26142-w"),
    ("03_Fuentes_2025_UEBA_deep_autoencoders.pdf",
     "https://arxiv.org/pdf/2505.11542",
     "https://doi.org/10.3934/math.20251043"),
    ("04_Villarreal-Vasquez_2023_LSTM_insider_hunting.pdf",
     "https://www.cs.purdue.edu/homes/bb/hunting.pdf",
     "https://doi.org/10.1109/TDSC.2021.3135639"),
    ("05_Li_2023_DD-GCN_insider_threat.pdf",
     None,
     "https://doi.org/10.1109/TIFS.2023.3245413"),
    ("06_Cai_2024_LAN_realtime_insider.pdf",
     "https://arxiv.org/pdf/2403.09209",
     "https://doi.org/10.1109/TIFS.2024.3488527"),
    ("07_Zhu_2024_AUTH_adversarial_autoencoder.pdf",
     None,
     "https://doi.org/10.1109/TII.2024.3393491"),
    ("08_King_2023_Euler_lateral_movement.pdf",
     "https://www2.seas.gwu.edu/~howie/publications/Euler-NDSS22.pdf",
     "https://doi.org/10.1145/3588771"),
    ("09_vanEde_2022_DeepCASE.pdf",
     "https://conand.me/publications/vanede-deepcase-2022.pdf",
     "https://doi.org/10.1109/SP46214.2022.9833671"),
    ("10_AlAhmadi_2022_99pct_false_positives_SOC.pdf",
     "https://www.usenix.org/system/files/sec22-alahmadi.pdf",
     "https://www.usenix.org/conference/usenixsecurity22/presentation/alahmadi"),
    ("11_Vermeer_2023_Alert_Alchemy_SOC.pdf",
     "https://repository.tudelft.nl/file/File_267d72ad-a929-4856-b913-a0f3202b7998",
     "https://doi.org/10.1145/3576915.3616581"),
    ("12_Kersten_2023_Give_me_structure_SOC.pdf",
     "https://www.usenix.org/system/files/soups2023-kersten.pdf",
     "https://www.usenix.org/conference/soups2023/presentation/kersten"),
    ("13_Oesch_2020_ML_tools_SOC_usability.pdf",
     "https://arxiv.org/pdf/2012.09013",
     "https://arxiv.org/abs/2012.09013"),
]


def ssl_context():
    # Python from python.org on macOS sometimes lacks root certificates; certifi fixes that.
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


def download(url: str, dest: Path, ctx) -> str:
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
        "Accept": "application/pdf,*/*"})
    with urllib.request.urlopen(req, timeout=60, context=ctx) as r:
        data = r.read()
    if not data.startswith(b"%PDF"):
        raise ValueError("the site returned a web page instead of a PDF")
    dest.write_bytes(data)
    return f"{len(data) / 1e6:.1f} MB"


def main():
    OUT.mkdir(exist_ok=True)
    ctx = ssl_context()
    ok, manual = [], []
    print(f"Saving papers to: {OUT}\n")
    for name, url, page in PAPERS:
        dest = OUT / name
        if dest.exists() and dest.stat().st_size > 10_000:
            print(f"  [skip]  {name} (already downloaded)")
            ok.append(name)
            continue
        if url is None:
            print(f"  [----]  {name} - paywalled, download manually")
            manual.append((name, page, "paywalled (IEEE) - use university IEEE Xplore login"))
            continue
        try:
            size = download(url, dest, ctx)
            print(f"  [ OK ]  {name} ({size})")
            ok.append(name)
        except Exception as e:  # noqa: BLE001
            print(f"  [FAIL]  {name} - {e}")
            manual.append((name, page, str(e)))
        time.sleep(1)  # be polite to the servers

    print(f"\nDownloaded {len(ok)} of {len(PAPERS)} papers.")
    if manual:
        print("\nOpen these in your browser and save the PDF into the 'papers' folder:")
        for name, page, why in manual:
            print(f"\n  {name}\n    link:   {page}\n    reason: {why}")
    return 0 if not manual else 1


if __name__ == "__main__":
    sys.exit(main())
