// Builds report/Report.docx from results/*.json and results/figures/*.png.
// Usage: node report/build_report.js   (then convert to PDF with LibreOffice)
const fs = require("fs");
const path = require("path");
const {
  Document, Packer, Paragraph, TextRun, AlignmentType, Footer, PageNumber,
  Table, TableRow, TableCell, WidthType, BorderStyle, ShadingType,
} = require("docx");
const L = require("./lib");
const refs = require("./references");

const ROOT = path.join(__dirname, "..");
const R = JSON.parse(fs.readFileSync(path.join(ROOT, "results/metrics.json")));
const S = JSON.parse(fs.readFileSync(path.join(ROOT, "results/response_summary.json")));
const MT = JSON.parse(fs.readFileSync(path.join(ROOT, "results/mixed_training.json")));
const PRETTY = {
  ind_win32_api: "Win32 API / injection indicators", ind_download: "Download-cradle indicators",
  log_length: "Script length (log)", log_lines: "Line count", mean_line_len: "Mean line length",
  log_max_line_len: "Longest line", entropy: "Shannon entropy", ratio_alpha: "Alphabetic ratio",
  ratio_digit: "Digit ratio", ratio_upper: "Upper-case ratio", ratio_whitespace: "Whitespace ratio",
  ratio_special: "Special-character ratio", ratio_brace: "Brace ratio", var_density: "Variable density",
  log_longest_token: "Longest token", comment_ratio: "Comment-line ratio",
};
const ctx = {
  MT,
  fig: (f) => path.join(ROOT, "results/figures", f),
  pretty: (f) => PRETTY[f] || f,
  ordinal: (k) => ["", "first", "second", "third", "fourth", "fifth", "sixth", "seventh", "eighth", "ninth", "tenth"][k] || `${k}th`,
  // Quote chosen n-grams (verifying they really are in the model's top list),
  // with visible markers for spaces and line breaks.
  ngrams: (list, chosen) => {
    for (const c of chosen) if (!list.includes(c)) throw new Error("n-gram not in top list: " + JSON.stringify(c));
    const show = (g) => "“" + g.replace(/\n/g, "\\n").replace(/ /g, "·") + "”";
    const q = chosen.map(show);
    return q.slice(0, -1).join(", ") + " and " + q[q.length - 1];
  },
  mitigationNarrative: (MT, M, G, tabN, nAug) => {
    const E = "Ensemble (TF-IDF LR + RF)";
    const pct = (x, d = 1) => (100 * x).toFixed(d) + "%";
    const models = Object.keys(MT.mixed_detection_rate);
    const best = models.reduce((a, b) => (MT.mixed_detection_rate[a] >= MT.mixed_detection_rate[b] ? a : b));
    const gain = MT.mixed_detection_rate[E] - M.detection_rate[E];
    const dFpr = MT.clean_test[E].fpr - G[E].fpr;
    const dF1 = MT.clean_test[E].f1 - G[E].f1;
    let verdict;
    if (gain > 0.2) verdict = `Adding realistic examples of embedded code to the training data therefore closes most of the gap. The price is a modest rise in false alarms on ordinary scripts (from ${pct(G[E].fpr, 2)} to ${pct(MT.clean_test[E].fpr, 2)}): having seen benign host code inside malicious-labelled samples, the model becomes slightly more suspicious of similar benign scripts. Because the tiered policy routes borderline scores to ALERT rather than to automatic containment, this trade-off is worthwhile, and mixed-aware training is recommended for the deployed model, with the false-positive rate re-measured on local data.`;
    else if (gain > 0.1) verdict = "Mixed-aware training therefore helps substantially, but the remaining gap shows that whole-script features alone cannot fully expose code that is hidden inside a long benign host; scoring individual functions or script blocks separately is a natural next step.";
    else verdict = "Augmentation alone therefore does not solve the problem; scoring smaller units, such as individual functions or script blocks, is needed so that the benign host cannot dilute the malicious part.";
    return `Following Fang et al., who included mixed scripts in training [@fang2021], the training folds were augmented with mixed samples. To prevent leakage, a mixed script was added to the training data of fold k only when *both* its malicious parent and its benign host belonged to the training folds (on average ${Math.round(nAug).toLocaleString("en-US")} scripts per fold); mixed scripts whose malicious parent lay in fold k were again held out for testing. Table ${tabN} shows the effect. For the ensemble, the detection rate on embedded payloads moved from ${pct(M.detection_rate[E])} to ${pct(MT.mixed_detection_rate[E])}, and ${pct(MT.mixed_alert_or_higher_rate[E])} of them now reach at least the ALERT tier, while its F1 on ordinary scripts changed by ${dF1 >= 0 ? "+" : "−"}${Math.abs(dF1).toFixed(3)} and its false-positive rate by ${dFpr >= 0 ? "+" : "−"}${(Math.abs(dFpr) * 100).toFixed(2)} percentage points. The best mixed-script detection after augmentation was achieved by ${best} (${pct(MT.mixed_detection_rate[best])}). ${verdict}`;
  },
  responseNarrative: (S, get, sdN, tierN) => {
    const mal = S.replayed_malicious, ben = S.replayed_benign;
    const silent = get("malicious", "ALLOW");
    const pct = (x, d = 1) => (100 * x).toFixed(d) + "%";
    return `Figure ${tierN} visualises the outcome. Of the ${mal} malicious events, ${get("malicious", "CONTAIN") + get("malicious", "ISOLATE")} (${pct(S.malicious_contained_rate, 1)}) were contained automatically—${get("malicious", "CONTAIN")} at the CONTAIN tier and ${get("malicious", "ISOLATE")} at the ISOLATE tier awaiting analyst approval—and a further ${get("malicious", "ALERT")} raised an ALERT, so only ${silent} (${pct(silent / mal, 1)}) passed without any signal reaching an analyst. On the benign side, ${get("benign", "ALLOW")} of ${ben} events (${pct(get("benign", "ALLOW") / ben, 1)}) were allowed silently, ${get("benign", "ALERT")} produced an alert and only ${get("benign", "CONTAIN")} (${pct(S.benign_contained_rate, 2)}) were wrongly contained. Figure ${sdN} explains why the tiers work: the out-of-fold risk scores of benign scripts are concentrated close to 0 and those of malicious scripts close to 1, and the ALERT band between 0.30 and 0.70 catches most of the genuinely uncertain cases, so that automated containment is applied almost only where the model is confident. The large number of isolation requests reflects how common process-injection loaders are in this dataset; in practice, approvals would be grouped per host, because several events usually come from the same compromised machine. Note that latency was measured in a shared four-core container while other experiments were running, so it is a conservative figure.`;
  },
};

// Edit these before submission.
const META = {
  group: "G__",
  members: [
    ["1", "[Student Name 1]", "[Roll / Enrolment No.]"],
    ["2", "[Student Name 2]", "[Roll / Enrolment No.]"],
    ["3", "[Student Name 3]", "[Roll / Enrolment No.]"],
    ["4", "[Student Name 4]", "[Roll / Enrolment No.]"],
  ],
  course: "Cyber Security — Case Study Report (Unit 4)",
  faculty: "[Name of Faculty / Course Coordinator]",
  dept: "[Department Name], [Institute Name]",
  year: "Academic Year 2026–27",
};
const TITLE = "AI-Powered Detection and Automated Response to Malicious PowerShell Attacks Using Machine Learning";

L.defineRefs(refs);
const { FONT, BLUE, P, H1 } = L;

const t = (text, o = {}) => new TextRun({ text, font: FONT, size: 24, ...o });
const centre = (children, after = 120) => new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after }, children });

function titlePage() {
  const b = { style: BorderStyle.SINGLE, size: 4, color: "7F9CC4" };
  const borders = { top: b, bottom: b, left: b, right: b };
  const W = [1200, 4500, 3326];
  const row = (cells, head) => new TableRow({
    children: cells.map((c, i) => new TableCell({
      borders, width: { size: W[i], type: WidthType.DXA },
      shading: head ? { fill: "DCE7F5", type: ShadingType.CLEAR, color: "auto" } : undefined,
      margins: { top: 70, bottom: 70, left: 110, right: 110 },
      children: [new Paragraph({ alignment: i === 0 ? AlignmentType.CENTER : AlignmentType.LEFT,
        children: [t(c, head ? { bold: true, color: BLUE } : {})] })],
    })),
  });
  return [
    centre([t(META.course.toUpperCase(), { bold: true, color: BLUE })], 600),
    centre([t(TITLE, { bold: true, size: 36, color: BLUE })], 500),
    centre([t("Group No.: ", { bold: true, size: 28 }), t(META.group, { size: 28 })], 200),
    centre([t("Topic Selected: ", { bold: true }), t(TITLE)], 400),
    centre([t("Group Members", { bold: true, color: BLUE })], 120),
    new Table({ width: { size: 9026, type: WidthType.DXA }, columnWidths: W,
      rows: [row(["Sr. No.", "Name of Student", "Roll / Enrolment No."], true), ...META.members.map((m) => row(m))] }),
    centre([], 500),
    centre([t("Submitted to: ", { bold: true }), t(META.faculty)]),
    centre([t(META.dept)]),
    centre([t(META.year)]),
    centre([t("October 2026")]),
    L.pageBreak(),
  ];
}

const g = R.group_split["Ensemble (TF-IDF LR + RF)"];
const nv = R.naive_random_split["Ensemble (TF-IDF LR + RF)"];
const pct = (x, d = 1) => (100 * x).toFixed(d) + "%";
const c = R.cleaning;

function abstract() {
  const dup = (c.raw_counts.malicious_pure - c.final_counts.malicious_pure - c.label_conflicts_removed / 2) / c.raw_counts.malicious_pure;
  return [
    H1("Abstract"),
    P(`PowerShell is installed on every modern Windows computer, and the features that make it useful to administrators—direct access to .NET and Windows APIs, in-memory execution and remote management—also make it a favourite tool of attackers who want to “live off the land”. Signature-based antivirus copes poorly with such scripts, because a payload can be renamed, re-encoded or split into fragments without changing its behaviour. This case study designs, implements and evaluates a machine-learning pipeline that classifies PowerShell script blocks as malicious or benign and then drives a tiered automated response. The public MPSD corpus (${c.raw_counts.malicious_pure.toLocaleString("en-US")} malicious and ${c.raw_counts.powershell_benign_dataset.toLocaleString("en-US")} benign scripts) was first audited: ${pct(dup, 0)} of the malicious files were exact duplicates, ${c.label_conflicts_removed} files carried both labels, and byte-order marks appeared only in benign files. After cleaning, ${c.final_counts.malicious_pure.toLocaleString("en-US")} malicious and ${c.final_counts.powershell_benign_dataset.toLocaleString("en-US")} benign scripts remained, and the malicious scripts collapsed into ${c.skeleton_groups.malicious_pure} structural families. Character 3–5-gram TF-IDF features were combined with 33 interpretable statistical and behavioural indicators mapped to MITRE ATT&CK, and logistic regression, random forest, gradient boosting and a soft-voting ensemble were compared under family-aware five-fold cross-validation. The ensemble achieved an F1-score of ${g.f1.toFixed(3)} and a ROC-AUC of ${g.roc_auc.toFixed(4)}, detecting ${pct(g.tpr_at_fpr_1pct)} of malicious scripts at a 1% false-positive rate. A naive random split on the uncleaned data reported ${pct(nv.tpr_at_fpr_1pct)} for the same measure, showing how duplicate leakage inflates published results. Malicious code hidden inside long benign scripts proved to be the main weakness: only ${pct(R.mixed_embedded.detection_rate["Ensemble (TF-IDF LR + RF)"])} of such samples were detected, rising to ${pct(MT.mixed_detection_rate["Ensemble (TF-IDF LR + RF)"])} when comparable examples were added to training, at the cost of a small increase in false positives. A response engine that consumes Windows Event ID 4104 records replayed an unseen fold of ${S.replayed_events.toLocaleString("en-US")} scripts: it contained ${pct(S.malicious_contained_rate)} of malicious scripts, wrongly contained ${pct(S.benign_contained_rate, 2)} of benign ones and needed a median of ${S.latency_ms.median.toFixed(1)} ms per event. The results show that lightweight, explainable models paired with a proportionate, human-supervised response policy can provide practical protection against PowerShell-based attacks.`),
    new Paragraph({ spacing: { before: 120, after: 240 }, alignment: AlignmentType.JUSTIFIED, children: [
      t("Keywords: ", { bold: true, color: BLUE }),
      t("PowerShell; malware detection; machine learning; living-off-the-land attacks; TF-IDF; random forest; ensemble learning; MITRE ATT&CK; automated incident response; SOAR; Script Block Logging; AMSI."),
    ] }),
  ];
}

const sectionsA = require("./sections_a");
const sectionsB = require("./sections_b");

const body = [
  ...abstract(),
  ...sectionsA(R, ctx),
  ...sectionsB(R, S, ctx),
  H1("References"),
];
const refBlocks = L.referenceList();

const doc = new Document({
  creator: "Group " + META.group,
  title: TITLE,
  description: "Cyber Security case study report",
  styles: {
    default: { document: { run: { font: FONT, size: 24, color: "000000" } } },
    paragraphStyles: [
      { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { font: FONT, size: 28, bold: true, color: BLUE }, paragraph: { outlineLevel: 0 } },
      { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { font: FONT, size: 24, bold: true, color: BLUE }, paragraph: { outlineLevel: 1 } },
      { id: "Heading3", name: "Heading 3", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { font: FONT, size: 24, bold: true, italics: true, color: BLUE }, paragraph: { outlineLevel: 2 } },
    ],
  },
  numbering: L.numberingConfig,
  sections: [
    {
      properties: { page: { size: { width: 11906, height: 16838 },
        margin: { top: 1440, bottom: 1440, left: 1440, right: 1440 } } },
      children: titlePage(),
    },
    {
      properties: { page: { size: { width: 11906, height: 16838 },
        margin: { top: 1440, bottom: 1440, left: 1440, right: 1440 },
        pageNumbers: { start: 1 } } },
      footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER,
        children: [new TextRun({ children: [PageNumber.CURRENT], font: FONT, size: 24 })] })] }) },
      children: [...body, ...refBlocks],
    },
  ],
});

Packer.toBuffer(doc).then((buf) => {
  const out = path.join(__dirname, "Report.docx");
  fs.writeFileSync(out, buf);
  console.log("wrote", out, "with", refBlocks.length, "references");
});
