"""Build the UEBA review paper as a .docx in the same layout as the template paper.

    uv run -q --no-project --with python-docx python review_paper/build_review.py
    soffice --headless --convert-to pdf --outdir review_paper review_paper/UEBA_Review_Paper_Amaan_Saify.docx

The template's styles, page size, margins and bullet numbering are reused; its body is replaced.
"""
import copy
import re
import sys
from pathlib import Path

import docx
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Pt

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import content as C  # noqa: E402

OUT = HERE / "UEBA_Review_Paper_Amaan_Saify.docx"
d = docx.Document(HERE / "template_reference.docx")

# bullet numbering id used by the template's list paragraphs
tmpl_xml = d.element.body.xml
m = re.search(r'<w:numPr>\s*<w:ilvl w:val="0"/>\s*<w:numId w:val="(\d+)"/>', tmpl_xml)
BULLET_NUM_ID = m.group(1) if m else None

# clear the body, keep the final section properties
body = d.element.body
for el in list(body):
    if el.tag != qn("w:sectPr"):
        body.remove(el)

# ------------------------------------------------------------------ citations
order = []


def cite(text):
    def repl(mo):
        nums = []
        for k in mo.group(1).split(","):
            k = k.strip()
            if k not in C.REFS:
                raise KeyError(f"unknown reference key: {k}")
            if k not in order:
                order.append(k)
            nums.append(order.index(k) + 1)
        return "[" + ", ".join(str(n) for n in nums) + "]"
    return re.sub(r"\{([a-z0-9_, ]+)\}", repl, text)


# ------------------------------------------------------------------ helpers
def para(text="", size=11, bold=False, after=10, style=None, italic=False):
    p = d.add_paragraph(style=style)
    p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    p.paragraph_format.space_after = Pt(after)
    if text:
        r = p.add_run(text)
        r.bold = bold or None
        r.italic = italic or None
        r.font.size = Pt(size)
    return p


def h1(text):
    p = para(text, size=13, bold=True, after=8, style="Heading 1")
    p.paragraph_format.keep_with_next = True


def h2(text):
    p = para(text, size=12, bold=True, after=6, style="Heading 2")
    p.paragraph_format.keep_with_next = True


def bullet(label, text):
    p = para(style="List Paragraph", after=5)
    if BULLET_NUM_ID:
        pPr = p._p.get_or_add_pPr()
        numPr = OxmlElement("w:numPr")
        ilvl = OxmlElement("w:ilvl"); ilvl.set(qn("w:val"), "0")
        num = OxmlElement("w:numId"); num.set(qn("w:val"), BULLET_NUM_ID)
        numPr.append(ilvl); numPr.append(num)
        ps = pPr.find(qn("w:pStyle"))
        if ps is not None:
            ps.addnext(numPr)
        else:
            pPr.insert(0, numPr)
    r = p.add_run(label + ": "); r.bold = True; r.font.size = Pt(11)
    r = p.add_run(cite(text)); r.font.size = Pt(11)


def shade(cell, fill):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear"); shd.set(qn("w:color"), "auto"); shd.set(qn("w:fill"), fill)
    tcPr.append(shd)


def cell_margins(cell):
    tcPr = cell._tc.get_or_add_tcPr()
    mar = OxmlElement("w:tcMar")
    for side, w in (("top", 70), ("left", 90), ("bottom", 70), ("right", 90)):
        e = OxmlElement(f"w:{side}"); e.set(qn("w:w"), str(w)); e.set(qn("w:type"), "dxa")
        mar.append(e)
    tcPr.append(mar)


def table(caption, header, rows, widths):
    cap = para(after=4)
    cap.paragraph_format.keep_with_next = True
    r = cap.add_run(caption.split(" ", 2)[0] + " " + caption.split(" ", 2)[1] + " ")
    r.bold = True; r.font.size = Pt(10)
    r = cap.add_run(caption.split(" ", 2)[2]); r.font.size = Pt(10)

    t = d.add_table(rows=1 + len(rows), cols=len(header))
    tblPr = t._tbl.tblPr
    tblW = tblPr.find(qn("w:tblW"))
    if tblW is None:
        tblW = OxmlElement("w:tblW"); tblPr.append(tblW)
    tblW.set(qn("w:w"), str(sum(widths))); tblW.set(qn("w:type"), "dxa")
    borders = OxmlElement("w:tblBorders")
    for side in ("top", "left", "bottom", "right", "insideH", "insideV"):
        e = OxmlElement(f"w:{side}")
        e.set(qn("w:val"), "single"); e.set(qn("w:sz"), "4"); e.set(qn("w:space"), "0"); e.set(qn("w:color"), "auto")
        borders.append(e)
    tblPr.append(borders)
    layout = OxmlElement("w:tblLayout"); layout.set(qn("w:type"), "fixed"); tblPr.append(layout)
    grid = t._tbl.tblGrid
    for gc, w in zip(grid.findall(qn("w:gridCol")), widths):
        gc.set(qn("w:w"), str(w))
    # repeat header row on each page
    for k, row in enumerate(t.rows):
        trPr = row._tr.get_or_add_trPr()
        trPr.append(OxmlElement("w:cantSplit"))
        if k == 0:
            trPr.append(OxmlElement("w:tblHeader"))

    for i, row in enumerate([header] + list(rows)):
        for j, txt in enumerate(row):
            c = t.rows[i].cells[j]
            c.width = docx.shared.Twips(widths[j])
            cell_margins(c)
            if i == 0:
                shade(c, "D9E2F3")
            p = c.paragraphs[0]
            p.paragraph_format.space_after = Pt(0)
            run = p.add_run(cite(txt))
            run.font.size = Pt(9)
            run.bold = (i == 0) or None
    para(after=6)


# ------------------------------------------------------------------ front matter
para(C.TITLE, size=16, bold=True, after=12)
para(C.AUTHORS, after=3)
para(C.SUPERVISOR, after=3)
para(after=3)
para("Abstract", size=12, bold=True, after=6)
para(C.ABSTRACT, after=10)
kw = para(after=13)
r = kw.add_run("Keywords: "); r.bold = True; r.font.size = Pt(11)
r = kw.add_run(C.KEYWORDS); r.italic = True; r.font.size = Pt(11)

# ------------------------------------------------------------------ body
for block in C.BODY:
    kind = block[0]
    if kind == "h1":
        h1(block[1])
    elif kind == "h2":
        h2(block[1])
    elif kind == "p":
        para(cite(block[1]), after=10)
    elif kind == "bullets":
        for label, text in block[1]:
            bullet(label, text)
        para(after=4)
    elif kind == "table":
        table(*block[1:])
    else:
        raise ValueError(kind)

h1("Declaration of Competing Interest")
para(C.DECLARATION, after=10)

h1("References")
unused = [k for k in C.REFS if k not in order]
if unused:
    raise SystemExit(f"references never cited: {unused}")
for n, key in enumerate(order, 1):
    p = para(after=7)
    p.alignment = WD_ALIGN_PARAGRAPH.LEFT
    r = p.add_run(f"[{n}] "); r.bold = True; r.font.size = Pt(10.5)
    r = p.add_run(C.REFS[key]); r.font.size = Pt(10.5)

d.core_properties.title = C.TITLE
d.core_properties.author = C.AUTHORS
d.save(OUT)
words = sum(len(p.text.split()) for p in d.paragraphs)
print(f"wrote {OUT.name}: {len(order)} references, ~{words} words in paragraphs")
