// Small layout layer over docx-js: Times New Roman 12 pt body, black text,
// blue headings/table headers, single column, IEEE-style numeric citations.
const fs = require("fs");
const {
  Paragraph, TextRun, HeadingLevel, AlignmentType, Table, TableRow, TableCell,
  WidthType, BorderStyle, ShadingType, ImageRun, LevelFormat, PageBreak,
} = require("docx");

const FONT = "Times New Roman";
const BLUE = "1F3A68";
const LIGHT_BLUE = "DCE7F5";
const BODY_PT = 24; // half-points -> 12 pt
const CONTENT_W = 9026; // A4 width 11906 minus 2 x 1440 margins

const refs = {};       // key -> formatted reference text
const citeOrder = [];  // keys in order of first citation
let figN = 0;
let tabN = 0;

function defineRefs(list) {
  for (const [k, v] of list) refs[k] = v;
}

function citeNum(key) {
  if (!refs[key]) throw new Error("unknown reference " + key);
  let i = citeOrder.indexOf(key);
  if (i < 0) { citeOrder.push(key); i = citeOrder.length - 1; }
  return i + 1;
}

// Inline markup: **bold**, *italic*, _{sub}, ^{sup}, [@key1,key2] citations.
function runs(text, base = {}) {
  const out = [];
  const re = /(\*\*[^*]+\*\*|\*[^*]+\*|_\{[^}]+\}|\^\{[^}]+\}|\[@[^\]]+\])/g;
  let last = 0;
  let m;
  const push = (t, extra = {}) => {
    if (t) out.push(new TextRun({ text: t, font: FONT, size: BODY_PT, ...base, ...extra }));
  };
  while ((m = re.exec(text)) !== null) {
    push(text.slice(last, m.index));
    const tok = m[0];
    if (tok.startsWith("**")) push(tok.slice(2, -2), { bold: true });
    else if (tok.startsWith("_{")) push(tok.slice(2, -1), { subScript: true });
    else if (tok.startsWith("^{")) push(tok.slice(2, -1), { superScript: true });
    else if (tok.startsWith("[@")) {
      const nums = tok.slice(2, -1).split(",").map((k) => citeNum(k.trim()));
      push("[" + compress(nums) + "]");
    } else push(tok.slice(1, -1), { italics: true });
    last = m.index + tok.length;
  }
  push(text.slice(last));
  return out;
}

function compress(nums) {
  // [3], [3, 5], [3]-[5] in IEEE style
  const s = [...new Set(nums)].sort((a, b) => a - b);
  const parts = [];
  for (let i = 0; i < s.length; i++) {
    let j = i;
    while (j + 1 < s.length && s[j + 1] === s[j] + 1) j++;
    parts.push(j - i >= 2 ? `${s[i]}]–[${s[j]}` : s.slice(i, j + 1).join("], ["));
    i = j;
  }
  return parts.join("], [");
}

const SP = { line: 276, after: 120 }; // 1.15 line spacing, 6 pt after

function P(text, opts = {}) {
  return new Paragraph({
    alignment: opts.align || AlignmentType.JUSTIFIED,
    spacing: { ...SP, ...(opts.spacing || {}) },
    indent: opts.indent,
    keepNext: opts.keepNext,
    children: runs(text, opts.run || {}),
  });
}

function H1(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_1,
    spacing: { before: 300, after: 140 },
    keepNext: true,
    children: [new TextRun({ text, font: FONT, size: 28, bold: true, color: BLUE })],
  });
}
function H2(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_2,
    spacing: { before: 220, after: 100 },
    keepNext: true,
    children: [new TextRun({ text, font: FONT, size: BODY_PT, bold: true, color: BLUE })],
  });
}
function H3(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_3,
    spacing: { before: 160, after: 80 },
    keepNext: true,
    children: [new TextRun({ text, font: FONT, size: BODY_PT, bold: true, italics: true, color: BLUE })],
  });
}

function bullets(items, ref = "bullets") {
  return items.map((t) => new Paragraph({
    numbering: { reference: ref, level: 0 },
    alignment: AlignmentType.JUSTIFIED,
    spacing: { line: 276, after: 60 },
    children: runs(t),
  }));
}

function numbered(items, ref) {
  return bullets(items, ref);
}

function equation(text, label) {
  return new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { before: 60, after: 120, line: 276 },
    children: [...runs(text, { italics: false }),
      ...(label ? [new TextRun({ text: `\t\t(${label})`, font: FONT, size: BODY_PT })] : [])],
  });
}

function pngSize(path) {
  const b = fs.readFileSync(path);
  return { w: b.readUInt32BE(16), h: b.readUInt32BE(20) };
}

function figure(path, caption, widthIn = 6.0) {
  figN += 1;
  const { w, h } = pngSize(path);
  const wpx = Math.round(widthIn * 96);
  const hpx = Math.round((wpx * h) / w);
  return {
    n: figN,
    blocks: [
      new Paragraph({
        alignment: AlignmentType.CENTER,
        keepNext: true,
        spacing: { before: 120, after: 60 },
        children: [new ImageRun({
          type: "png", data: fs.readFileSync(path),
          transformation: { width: wpx, height: hpx },
          altText: { title: `Figure ${figN}`, description: caption, name: `fig${figN}` },
        })],
      }),
      new Paragraph({
        alignment: AlignmentType.CENTER,
        spacing: { after: 200, line: 240 },
        children: [new TextRun({ text: `Figure ${figN}: `, font: FONT, size: BODY_PT, bold: true }),
          ...runs(caption)],
      }),
    ],
  };
}

const border = { style: BorderStyle.SINGLE, size: 4, color: "7F9CC4" };
const borders = { top: border, bottom: border, left: border, right: border };

function table(caption, header, rows, widths) {
  tabN += 1;
  const total = widths.reduce((a, b) => a + b, 0);
  const scale = CONTENT_W / total;
  const w = widths.map((x) => Math.floor(x * scale));
  w[w.length - 1] += CONTENT_W - w.reduce((a, b) => a + b, 0);
  const NUMERIC = /^[\d\s.,%→\-–\/≈<>≥≤()+]+$/;
  const cell = (text, i, isHead, keep) => new TableCell({
    borders,
    width: { size: w[i], type: WidthType.DXA },
    shading: isHead ? { fill: LIGHT_BLUE, type: ShadingType.CLEAR, color: "auto" } : undefined,
    margins: { top: 50, bottom: 50, left: 90, right: 90 },
    children: String(text).split("\n").map((line) => new Paragraph({
      alignment: i > 0 && NUMERIC.test(line) ? AlignmentType.CENTER : AlignmentType.LEFT,
      spacing: { line: 240, after: 0 },
      keepNext: keep,
      children: runs(line, isHead ? { bold: true, color: BLUE } : {}),
    })),
  });
  return {
    n: tabN,
    blocks: [
      new Paragraph({
        alignment: AlignmentType.CENTER,
        keepNext: true,
        spacing: { before: 160, after: 80, line: 240 },
        children: [new TextRun({ text: `Table ${tabN}: `, font: FONT, size: BODY_PT, bold: true }),
          ...runs(caption)],
      }),
      new Table({
        width: { size: CONTENT_W, type: WidthType.DXA },
        columnWidths: w,
        rows: [
          new TableRow({ tableHeader: true, children: header.map((h, i) => cell(h, i, true, true)) }),
          // keep-with-next on every row but the last keeps short tables on one page
          ...rows.map((r, ri) => new TableRow({ cantSplit: true,
            children: r.map((c, i) => cell(c, i, false, ri < rows.length - 1 && rows.length <= 12)) })),
        ],
      }),
      new Paragraph({ spacing: { after: 120 }, children: [] }),
    ],
  };
}

function referenceList() {
  const uncited = Object.keys(refs).filter((k) => !citeOrder.includes(k));
  if (uncited.length) throw new Error("uncited references: " + uncited.join(", "));
  return citeOrder.map((k, i) => new Paragraph({
    alignment: AlignmentType.LEFT,
    spacing: { line: 252, after: 100 },
    indent: { left: 567, hanging: 567 },
    children: [new TextRun({ text: `[${i + 1}]\t`, font: FONT, size: BODY_PT }), ...runs(refs[k])],
  }));
}

function pageBreak() {
  return new Paragraph({ children: [new PageBreak()] });
}

const numberingConfig = {
  config: [
    { reference: "bullets", levels: [{ level: 0, format: LevelFormat.BULLET, text: "•",
      alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 567, hanging: 283 } } } }] },
    ...["obj", "contrib", "steps", "alg", "future"].map((r) => ({
      reference: r, levels: [{ level: 0, format: LevelFormat.DECIMAL, text: "%1.",
        alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 567, hanging: 340 } } } }],
    })),
  ],
};

module.exports = {
  FONT, BLUE, BODY_PT, CONTENT_W, defineRefs, runs, P, H1, H2, H3, bullets, numbered,
  equation, figure, table, referenceList, pageBreak, numberingConfig, citeNum,
};
