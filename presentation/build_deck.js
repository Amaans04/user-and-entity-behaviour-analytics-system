// Builds the class presentation for the UEBA in-house project.
// Run from this folder:  node build_deck.js   ->  ~/Downloads/UEBA_Project_Presentation.pptx
const path = require("path");
const os = require("os");
const pptxgen = require("pptxgenjs");
const React = require("react");
const ReactDOMServer = require("react-dom/server");
const sharp = require("sharp");
const fa = require("react-icons/fa");
const { applyTheme } = require(process.env.PPTX_SKILL + "/scripts/apply_theme.js");

const NOTES = require("./script.json").map((sl) =>
  sl.parts.map((p) => `${p.who.toUpperCase()} (${sl.time} for this slide):\n${p.text}`).join("\n\n"));
const OUT = path.join(os.homedir(), "Downloads", "UEBA_Project_Presentation.pptx");
const SCREENS = path.join(__dirname, "..", "report", "screens");

const THEME = {
  name: "UEBA Night Watch",
  headFontFace: "Arial",
  bodyFontFace: "Calibri",
  colors: {
    dk1: "0B1220", lt1: "FFFFFF", dk2: "102A43", lt2: "EEF3F8",
    accent1: "0FB5A6", accent2: "F5A524", accent3: "E5484D", accent4: "5B6B8C",
    accent5: "3E7BFA", accent6: "8B5CF6", hlink: "0FB5A6", folHlink: "5B6B8C",
  },
};
const HEX = THEME.colors;

const W = 13.333, H = 7.5, MX = 0.6;

async function icon(Comp, color, size = 256) {
  const svg = ReactDOMServer.renderToStaticMarkup(React.createElement(Comp, { color: "#" + color, size }));
  const png = await sharp(Buffer.from(svg)).resize(size, size).png().toBuffer();
  return "image/png;base64," + png.toString("base64");
}

(async () => {
  const pres = new pptxgen();
  pres.layout = "LAYOUT_WIDE";
  pres.title = "AI-Based User and Entity Behaviour Analytics System";
  pres.author = "Amaan Saify, Tarun Jadhav";
  pres.company = "Alliance University";
  pres.theme = { headFontFace: THEME.headFontFace, bodyFontFace: THEME.bodyFontFace };
  const C = pres.SchemeColor;

  // ---------------------------------------------------------------- layouts
  pres.defineSlideMaster({
    title: "TITLE_DARK",
    background: { color: HEX.dk2 },
    objects: [
      { placeholder: { options: { name: "title", type: "title", x: MX, y: 2.05, w: 8.4, h: 1.9, fontSize: 40, bold: true,
                                  color: C.background1, valign: "top", align: "left", margin: 0 }, text: "" } },
      { placeholder: { options: { name: "body", type: "body", x: MX, y: 4.0, w: 8.4, h: 0.6, fontSize: 18,
                                  color: C.background2, italic: true, align: "left", margin: 0 }, text: "" } },
    ],
  });
  pres.defineSlideMaster({
    title: "CONTENT",
    background: { color: HEX.lt1 },
    margin: [0.5, 0.6, 0.7, 0.6],
    objects: [
      { placeholder: { options: { name: "title", type: "title", x: MX, y: 0.78, w: W - 2 * MX, h: 0.85, fontSize: 32,
                                  bold: true, color: C.text2, valign: "top", align: "left", margin: 0 }, text: "" } },
      { text: { text: "AI-Based UEBA System  ·  Alliance University", options: { x: MX, y: 7.0, w: 7, h: 0.3,
                fontSize: 10, color: C.accent4, margin: 0 } } },
    ],
    slideNumber: { x: W - MX - 0.6, y: 7.0, w: 0.6, h: 0.3, fontSize: 10, color: HEX.accent4, align: "right" },
  });
  pres.defineSlideMaster({
    title: "CLOSING_DARK",
    background: { color: HEX.dk2 },
    objects: [
      { placeholder: { options: { name: "title", type: "title", x: MX, y: 0.78, w: W - 2 * MX, h: 0.85, fontSize: 32,
                                  bold: true, color: C.background1, valign: "top", align: "left", margin: 0 }, text: "" } },
    ],
  });

  // ---------------------------------------------------------------- helpers
  const kicker = (s, text, dark = false) => s.addText(text, {
    x: MX, y: 0.42, w: 10, h: 0.3, fontSize: 12, bold: true, charSpacing: 3, margin: 0, isTextBox: true,
    color: dark ? C.accent1 : C.accent1, objectName: "Kicker" });
  const circleIcon = async (s, Comp, x, y, d, fill, fg = HEX.lt1, name = "Icon") => {
    s.addShape(pres.shapes.OVAL, { x, y, w: d, h: d, fill: { color: fill }, line: { type: "none" }, objectName: name + " circle" });
    const pad = d * 0.25;
    s.addImage({ data: await icon(Comp, fg), x: x + pad, y: y + pad, w: d - 2 * pad, h: d - 2 * pad, objectName: name,
                 altText: name });
  };
  const card = (s, x, y, w, h, fill = HEX.lt2, name = "Card") => s.addShape(pres.shapes.ROUNDED_RECTANGLE, {
    x, y, w, h, rectRadius: 0.12, fill: { color: fill }, line: { type: "none" }, objectName: name });
  const T = (s, text, o) => s.addText(text, Object.assign({ isTextBox: true, margin: 0, valign: "top" }, o));

  // ================================================================ 1. title
  pres.addSection({ title: "Introduction" });
  let s = pres.addSlide({ masterName: "TITLE_DARK", sectionTitle: "Introduction" });
  T(s, "IN-HOUSE PROJECT  ·  B.TECH CSE (CYBER SECURITY)", { x: MX, y: 1.45, w: 8.4, h: 0.35, fontSize: 13, bold: true,
    color: C.accent1, charSpacing: 3, objectName: "Programme" });
  s.addText("AI-Based User & Entity Behaviour Analytics System", { placeholder: "title" });
  s.addText("Learning what normal looks like, and catching what isn't", { placeholder: "body" });
  // presenters
  const people = [["Amaan Saify", "Presenter"], ["Tarun Jadhav", "Presenter"]];
  people.forEach(([n, r], i) => {
    const x = MX + i * 3.3;
    T(s, n, { x, y: 5.05, w: 3.1, h: 0.4, fontSize: 20, bold: true, color: C.background1, objectName: "Name " + (i + 1) });
    T(s, "7th Semester  ·  Batch 2023–2027", { x, y: 5.45, w: 3.1, h: 0.3, fontSize: 13, color: C.background2,
      objectName: "Batch " + (i + 1) });
  });
  T(s, "Under the supervision of Dr. Rathnakar Achary, Associate Professor\nAlliance School of Advanced Computing  ·  Alliance University, Bengaluru",
    { x: MX, y: 6.25, w: 9, h: 0.7, fontSize: 13, color: C.background2, objectName: "Supervisor" });
  // emblem
  s.addShape(pres.shapes.OVAL, { x: 9.55, y: 1.75, w: 3.2, h: 3.2, fill: { color: HEX.accent1, transparency: 82 },
    line: { color: HEX.accent1, width: 1.5 }, objectName: "Emblem ring" });
  s.addShape(pres.shapes.OVAL, { x: 10.0, y: 2.2, w: 2.3, h: 2.3, fill: { color: HEX.accent1 }, line: { type: "none" },
    objectName: "Emblem" });
  s.addImage({ data: await icon(fa.FaUserShield, HEX.dk2), x: 10.55, y: 2.75, w: 1.2, h: 1.2, objectName: "Shield icon",
    altText: "Shield with a user" });
  s.addNotes(NOTES[0]);

  // ================================================================ 2. problem
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Introduction" });
  kicker(s, "01  ·  THE PROBLEM");
  s.addText("Attackers who log in look like employees", { placeholder: "title" });
  const cols = [
    { icon: fa.FaFingerprint, fill: HEX.accent4, head: "Signature-based tools",
      q: "Is this a known-bad pattern?",
      body: ["Match known malware and attack signatures", "Miss stolen passwords and insiders", "Miss techniques never seen before"] },
    { icon: fa.FaUserCheck, fill: HEX.accent1, head: "Behaviour analytics (UEBA)",
      q: "Is this normal for this person?",
      body: ["Learn each user's and device's habits", "Flag unusual hours, places and volumes", "Catch first-time and out-of-character actions"] },
  ];
  for (let i = 0; i < 2; i++) {
    const c = cols[i], x = MX + i * 6.15, y = 1.95, w = 5.95;
    card(s, x, y, w, 3.0, i ? "E6F7F5" : HEX.lt2, "Column card " + (i + 1));
    await circleIcon(s, c.icon, x + 0.35, y + 0.35, 0.75, c.fill, HEX.lt1, c.head + " icon");
    T(s, c.head, { x: x + 1.3, y: y + 0.38, w: w - 1.5, h: 0.4, fontSize: 20, bold: true, color: C.text2 });
    T(s, c.q, { x: x + 1.3, y: y + 0.8, w: w - 1.5, h: 0.35, fontSize: 15, italic: true, color: i ? C.accent1 : C.accent4 });
    T(s, c.body.map((b, k) => ({ text: b, options: { bullet: true, breakLine: k < c.body.length - 1 } })),
      { x: x + 0.4, y: y + 1.45, w: w - 0.8, h: 1.4, fontSize: 15, color: C.text1, paraSpaceAfter: 6 });
  }
  T(s, "Real attack patterns the system is built to catch", { x: MX, y: 5.2, w: 8, h: 0.35, fontSize: 14, bold: true,
    color: C.text2, objectName: "Examples heading" });
  const ex = [[fa.FaClock, "A finance user logs in at 2:20 am and reads payroll"],
              [fa.FaCloudUploadAlt, "An employee uploads 3.3 GB to a new website"],
              [fa.FaUserCog, "A sales account suddenly runs admin commands"]];
  for (let i = 0; i < 3; i++) {
    const x = MX + i * 4.1;
    await circleIcon(s, ex[i][0], x, 5.68, 0.5, HEX.accent2, HEX.dk2, "Example icon " + (i + 1));
    T(s, ex[i][1], { x: x + 0.65, y: 5.65, w: 3.3, h: 0.7, fontSize: 14, color: C.text1, valign: "middle" });
  }
  s.addNotes(NOTES[1]);

  // ================================================================ 3. objectives
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Introduction" });
  kicker(s, "02  ·  OBJECTIVES");
  s.addText("What we set out to build", { placeholder: "title" });
  const obj = [
    [fa.FaUserClock, "Learn", "A personal and a department baseline for every user and device, from their own history"],
    [fa.FaSearch, "Detect", "Statistics, machine learning and threat rules together, with no labelled attacks needed"],
    [fa.FaCommentDots, "Explain", "Every alert says why in plain numbers, mapped to MITRE ATT&CK techniques"],
    [fa.FaDesktop, "Operate", "A working security console: log collection, cases, roles, audit and notifications"],
  ];
  for (let i = 0; i < 4; i++) {
    const x = MX + i * 3.07, y = 2.05, w = 2.87, h = 3.45;
    card(s, x, y, w, h, HEX.lt2, "Objective card " + (i + 1));
    await circleIcon(s, obj[i][0], x + 0.35, y + 0.4, 0.9, i % 2 ? HEX.dk2 : HEX.accent1, HEX.lt1, obj[i][1] + " icon");
    T(s, obj[i][1], { x: x + 0.35, y: y + 1.55, w: w - 0.7, h: 0.5, fontSize: 22, bold: true, color: C.text2 });
    T(s, obj[i][2], { x: x + 0.35, y: y + 2.15, w: w - 0.7, h: 1.9, fontSize: 15, color: C.text1 });
  }
  await circleIcon(s, fa.FaCode, MX, 5.85, 0.55, HEX.lt2, HEX.dk2, "Stack icon");
  T(s, [{ text: "Built with  ", options: { bold: true, color: HEX.dk2 } },
        { text: "Python · pandas · scikit-learn · Streamlit · SQLite · Plotly · Ollama (local language model)",
          options: { color: HEX.dk1 } }],
    { x: MX + 0.75, y: 5.85, w: 11, h: 0.55, fontSize: 15, valign: "middle", objectName: "Tech stack" });
  s.addNotes(NOTES[2]);

  // ================================================================ 4. research gap
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Introduction" });
  kicker(s, "03  ·  RELATED WORK");
  s.addText("Where existing research falls short", { placeholder: "title" });
  const hdr = (t) => ({ text: t, options: { bold: true, color: HEX.lt1, fill: { color: HEX.dk2 }, fontSize: 15 } });
  const rows = [
    [hdr("Capability"), hdr("Reviewed work (IEEE TIFS, TII, ACM TOPS)"), hdr("This project")],
    ["Needs labelled attacks?", "Yes - DD-GCN, LAN train on known insiders", "No - fully unsupervised + rules"],
    ["Who is profiled", "Users only, or hosts only", "Users and devices together"],
    ["Explains the alert", "Score only", "Plain-English reasons + ATT&CK"],
    ["False-alarm control", "Euler: AUC 0.99 but precision 0.006", "Layers must agree before an alert"],
    ["Usable day to day", "Offline experiments", "Live console, incremental scoring"],
  ];
  s.addTable(rows.map((r, i) => i === 0 ? r : r.map((c, j) => ({ text: c, options: {
    fontSize: 15, color: j === 2 ? HEX.dk2 : HEX.dk1, bold: j === 2, fill: { color: i % 2 ? HEX.lt1 : HEX.lt2 } } }))), {
    x: MX, y: 1.95, w: W - 2 * MX, colW: [3.0, 4.75, 4.38], rowH: 0.62, valign: "middle",
    border: { type: "solid", pt: 0.75, color: "D5DEE8" }, margin: [0, 0.12, 0, 0.12], objectName: "Gap table" });
  T(s, "The techniques exist. The contribution is combining them into one explainable, label-free system you can actually run.",
    { x: MX, y: 6.0, w: W - 2 * MX, h: 0.5, fontSize: 15, italic: true, color: C.accent4, objectName: "Gap takeaway" });
  s.addNotes(NOTES[3]);

  // ================================================================ 5. architecture
  pres.addSection({ title: "System" });
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "System" });
  kicker(s, "04  ·  ARCHITECTURE");
  s.addText("From raw logs to an explained alert", { placeholder: "title" });
  const steps = [
    [fa.FaFileAlt, "Collect", "Linux auth.log, Windows .evtx / Sysmon, web proxy, CSV"],
    [fa.FaFilter, "Normalise", "One common format; columns mapped automatically"],
    [fa.FaChartBar, "Profile", "44 user + 19 device features per day"],
    [fa.FaBrain, "Detect", "Stats + ML ensemble + 33 rules"],
    [fa.FaTachometerAlt, "Score", "0-100 risk; alert at 45+"],
    [fa.FaBell, "Respond", "Cases, AI summary, notifications"],
  ];
  const sw = 1.83, gap = 0.23;
  for (let i = 0; i < steps.length; i++) {
    const x = MX + i * (sw + gap), y = 2.1;
    card(s, x, y, sw, 3.1, i === 3 ? "E6F7F5" : HEX.lt2, "Step card " + (i + 1));
    await circleIcon(s, steps[i][0], x + (sw - 0.8) / 2, y + 0.3, 0.8, i === 3 ? HEX.accent1 : HEX.dk2, HEX.lt1,
      steps[i][1] + " icon");
    T(s, steps[i][1], { x: x + 0.1, y: y + 1.25, w: sw - 0.2, h: 0.4, fontSize: 18, bold: true, color: C.text2, align: "center" });
    T(s, steps[i][2], { x: x + 0.15, y: y + 1.7, w: sw - 0.3, h: 1.3, fontSize: 14, color: C.text1, align: "center" });
    if (i < steps.length - 1)
      s.addImage({ data: await icon(fa.FaChevronRight, HEX.accent1), x: x + sw + 0.02, y: y + 1.42, w: 0.19, h: 0.19,
                   objectName: "Arrow " + (i + 1), altText: "next step" });
  }
  const ways = "Logs arrive by upload, a watched drop folder, an authenticated REST API or an endpoint agent. " +
               "New data is scored incrementally in seconds, identical to a full re-run.";
  card(s, MX, 5.55, W - 2 * MX, 0.95, "FFF6E5", "Ingest note card");
  await circleIcon(s, fa.FaStream, MX + 0.25, 5.75, 0.55, HEX.accent2, HEX.dk2, "Ingest icon");
  T(s, ways, { x: MX + 1.0, y: 5.62, w: W - 2 * MX - 1.2, h: 0.8, fontSize: 15, color: C.text1, valign: "middle" });
  s.addNotes(NOTES[4]);

  // ================================================================ 6. detection
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "System" });
  kicker(s, "05  ·  DETECTION ENGINE");
  s.addText("Three layers that must agree", { placeholder: "title" });
  const layers = [
    [fa.FaUserAlt, "Behavioural statistics", HEX.dk2,
     ["Robust z-scores against the person's own history and their department peers", "Plain evidence: \"3,300 MB uploaded vs usual 1.2\""]],
    [fa.FaProjectDiagram, "Machine-learning ensemble", HEX.accent1,
     ["Isolation Forest", "Local Outlier Factor", "Neural-network autoencoder", "Unsupervised: trained on normal days only"]],
    [fa.FaShieldAlt, "Threat rules", HEX.accent2,
     ["33 rules mapped to MITRE ATT&CK", "Brute force, impossible travel, exfiltration", "Log clearing, encoded PowerShell, USB"]],
  ];
  for (let i = 0; i < 3; i++) {
    const x = MX + i * 4.1, y = 1.95, w = 3.9, h = 3.55;
    card(s, x, y, w, h, HEX.lt2, "Layer card " + (i + 1));
    await circleIcon(s, layers[i][0], x + 0.35, y + 0.35, 0.8, layers[i][2], i === 2 ? HEX.dk2 : HEX.lt1, layers[i][1] + " icon");
    T(s, layers[i][1], { x: x + 1.3, y: y + 0.45, w: w - 1.45, h: 0.65, fontSize: 18, bold: true, color: C.text2, valign: "middle" });
    const b = layers[i][3];
    T(s, b.map((t, k) => ({ text: t, options: { bullet: true, breakLine: k < b.length - 1 } })),
      { x: x + 0.35, y: y + 1.45, w: w - 0.6, h: 2.0, fontSize: 15, color: C.text1, paraSpaceAfter: 5 });
  }
  // fusion strip
  card(s, MX, 5.75, W - 2 * MX, 0.85, HEX.dk2, "Fusion card");
  T(s, [{ text: "Fused into one 0-100 risk score.  ", options: { bold: true, color: HEX.lt1 } },
        { text: "The threshold is set so one statistic alone can never raise an alert - ML or a rule must back it up. " +
                "Suspicious days are never learned as normal.", options: { color: "C9D6E3" } }],
    { x: MX + 0.35, y: 5.8, w: W - 2 * MX - 0.7, h: 0.75, fontSize: 15, valign: "middle" });
  s.addNotes(NOTES[5]);

  // ================================================================ 7. local AI
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "System" });
  kicker(s, "06  ·  GENERATIVE AI ASSISTANT");
  s.addText("A local language model explains every case", { placeholder: "title" });
  s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: MX, y: 1.95, w: 7.0, h: 4.02, rectRadius: 0.08,
    fill: { color: HEX.lt1 }, line: { color: "D5DEE8", width: 1 },
    shadow: { type: "outer", color: "102A43", opacity: 0.12, blur: 8, offset: 2, angle: 90 }, objectName: "Screenshot frame" });
  s.addImage({ path: path.join(__dirname, "ai_case.png"), x: MX, y: 1.95, w: 7.0, h: 4.02, objectName: "AI summary screenshot",
    altText: "AI case summary written by the local model for maria.singh: what happened, how serious, next steps" });
  T(s, "Real output from the console: case maria.singh, security log tampering", { x: MX, y: 6.12, w: 7.0, h: 0.3,
    fontSize: 11, italic: true, color: C.accent4, objectName: "Screenshot caption" });
  const aiPts = [
    [fa.FaRobot, "Qwen 2.5 7B through Ollama", "Runs on the laptop - no log data leaves the machine"],
    [fa.FaFileSignature, "Case summaries", "What happened, how serious, 3-5 next steps"],
    [fa.FaTerminal, "Command explainer", "What a PowerShell or sudo command does and why it is risky"],
    [fa.FaBalanceScale, "Explains, never decides", "Alerts come only from the detectors; log text is fenced off against prompt injection"],
  ];
  for (let i = 0; i < 4; i++) {
    const y = 1.95 + i * 1.12, x = 7.95;
    await circleIcon(s, aiPts[i][0], x, y + 0.05, 0.6, i === 3 ? HEX.accent2 : HEX.accent1, i === 3 ? HEX.dk2 : HEX.lt1,
      aiPts[i][1] + " icon");
    T(s, aiPts[i][1], { x: x + 0.8, y, w: 3.95, h: 0.35, fontSize: 16, bold: true, color: C.text2 });
    T(s, aiPts[i][2], { x: x + 0.8, y: y + 0.36, w: 3.95, h: 0.7, fontSize: 14, color: C.text1 });
  }
  s.addNotes(NOTES[6]);

  // ================================================================ 8. console
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "System" });
  kicker(s, "07  ·  THE CONSOLE");
  s.addText("A security console analysts can work in", { placeholder: "title" });
  s.addImage({ path: path.join(SCREENS, "01_overview.png"), x: MX, y: 1.95, w: 5.9, h: 3.69, objectName: "Overview screenshot",
    altText: "Security overview page with alerts per day and riskiest entities" });
  s.addImage({ path: path.join(SCREENS, "05_activity.png"), x: MX + 6.2, y: 1.95, w: 5.9, h: 3.69,
    sizing: { type: "cover", w: 5.9, h: 3.69 }, objectName: "Activity screenshot",
    altText: "User activity page showing a person's flagged steps" });
  T(s, "Overview", { x: MX, y: 5.75, w: 5.9, h: 0.35, fontSize: 16, bold: true, color: C.text2 });
  T(s, "Alerts per day, riskiest people, MITRE techniques, risk by department", { x: MX, y: 6.1, w: 5.9, h: 0.6,
    fontSize: 14, color: C.text1 });
  T(s, "User activity", { x: MX + 6.2, y: 5.75, w: 5.9, h: 0.35, fontSize: 16, bold: true, color: C.text2 });
  T(s, "What a person did that day - sites, downloads, blocks, files, USB, PowerShell - out-of-character steps flagged",
    { x: MX + 6.2, y: 6.1, w: 5.9, h: 0.6, fontSize: 14, color: C.text1 });
  s.addNotes(NOTES[7]);

  // ================================================================ 9. results
  pres.addSection({ title: "Results" });
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Results" });
  kicker(s, "08  ·  RESULTS");
  s.addText("It catches the attacks, with very few false alarms", { placeholder: "title" });
  const stats = [["12 / 12", "planted attacks caught on day one"], ["0.95", "F1 score (precision 0.94, recall 0.97)"],
                 ["1", "alert per day on average"], ["6 / 6", "attacks found in raw Linux, Windows and proxy logs"]];
  for (let i = 0; i < 4; i++) {
    const x = MX, y = 1.95 + i * 1.18;
    T(s, stats[i][0], { x, y, w: 2.3, h: 0.9, fontSize: 40, bold: true, color: i === 3 ? C.accent2 : C.accent1, valign: "middle",
      fontFace: "Arial" });
    T(s, stats[i][1], { x: x + 2.4, y, w: 3.3, h: 0.9, fontSize: 15, color: C.text1, valign: "middle" });
  }
  s.addChart(pres.charts.BAR, [{ name: "Attacks detected (%)", labels: ["Simulated company\n(12 attacks)",
      "Raw server logs\n(6 attacks)", "CERT r4.2 benchmark\n(36 insiders)"], values: [100, 100, 61] }], {
    x: 6.9, y: 1.85, w: 5.85, h: 4.45, barDir: "col", chartColors: [HEX.accent1, HEX.accent2, HEX.dk2],
    showTitle: true, title: "Attacks detected (%)", titleFontSize: 16, titleColor: HEX.dk2, titleFontFace: "+mj-lt",
    showValue: true, dataLabelPosition: "outEnd", dataLabelFontSize: 15, dataLabelColor: HEX.dk2, dataLabelFormatCode: "0\"%\"",
    dataLabelFontFace: "+mn-lt", catAxisLabelFontFace: "+mn-lt", valAxisLabelFontFace: "+mn-lt",
    catAxisLabelColor: HEX.accent4, catAxisLabelFontSize: 12, valAxisHidden: true, valAxisMaxVal: 115, valAxisMinVal: 0,
    valGridLine: { style: "none" }, catGridLine: { style: "none" }, showLegend: false, barGapWidthPct: 55,
    objectName: "Detection chart", altText: "Bar chart: 100% of simulated attacks, 100% of raw-log attacks, 61% of CERT insiders detected" });
  T(s, "CERT r4.2: public CMU insider-threat data we did not design - 22 of 36 held-out insiders at under one alert a day.",
    { x: 6.9, y: 6.38, w: 5.85, h: 0.45, fontSize: 11, italic: true, color: C.accent4 });
  s.addNotes(NOTES[8]);

  // ================================================================ 10. security & testing
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Results" });
  kicker(s, "09  ·  SECURE AND TESTED");
  s.addText("A security tool has to be secure itself", { placeholder: "title" });
  const sec = [
    [fa.FaKey, "Salted password hashes", "PBKDF2-SHA256, 310,000 iterations"],
    [fa.FaLock, "Lock-out", "5 failed logins lock the account for 15 minutes"],
    [fa.FaUsersCog, "Roles", "Viewer, analyst, admin - each sees only what it may change"],
    [fa.FaIdBadge, "Scoped API tokens", "One workspace per token, revocable, stored hashed"],
    [fa.FaClipboardList, "Audit trail", "Every login, verdict, upload and setting change recorded"],
    [fa.FaVial, "44 automated tests", "Including: incremental update = full re-run"],
  ];
  for (let i = 0; i < 6; i++) {
    const col = i % 3, row = Math.floor(i / 3);
    const x = MX + col * 4.1, y = 2.0 + row * 2.25, w = 3.9, h = 2.0;
    card(s, x, y, w, h, row ? "E6F7F5" : HEX.lt2, "Security card " + (i + 1));
    await circleIcon(s, sec[i][0], x + 0.3, y + 0.3, 0.7, row ? HEX.accent1 : HEX.dk2, HEX.lt1, sec[i][1] + " icon");
    T(s, sec[i][1], { x: x + 1.2, y: y + 0.3, w: w - 1.35, h: 0.7, fontSize: 17, bold: true, color: C.text2, valign: "middle" });
    T(s, sec[i][2], { x: x + 0.3, y: y + 1.12, w: w - 0.6, h: 0.8, fontSize: 14, color: C.text1 });
  }
  s.addNotes(NOTES[9]);

  // ================================================================ 11. limitations & future
  s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Results" });
  kicker(s, "10  ·  LIMITATIONS AND FUTURE WORK");
  s.addText("What we would improve next", { placeholder: "title" });
  const lim = ["Main results use a simulated company - hence the independent CERT benchmark",
               "Slow, gradual data theft (job-seeking insiders) is still mostly missed",
               "Registry, DLL and Active Directory events are not analysed yet"];
  const fut = ["Sequence-aware models for gradual insiders (LSTM / transformer over daily activity)",
               "More log sources: registry, cloud apps (Microsoft 365, Google Workspace)",
               "Let the AI assistant answer questions over the data and draft incident reports"];
  const twoCol = async (x, head, items, Ic, fill, fg) => {
    card(s, x, 1.95, 5.95, 3.95, HEX.lt2, head + " card");
    await circleIcon(s, Ic, x + 0.35, 2.25, 0.7, fill, fg, head + " icon");
    T(s, head, { x: x + 1.25, y: 2.3, w: 4.4, h: 0.6, fontSize: 20, bold: true, color: C.text2, valign: "middle" });
    T(s, items.map((t, k) => ({ text: t, options: { bullet: true, breakLine: k < items.length - 1 } })),
      { x: x + 0.4, y: 3.15, w: 5.2, h: 2.6, fontSize: 16, color: C.text1, paraSpaceAfter: 12 });
  };
  await twoCol(MX, "Limitations", lim, fa.FaExclamationTriangle, HEX.accent2, HEX.dk2);
  await twoCol(MX + 6.15, "Future work", fut, fa.FaRocket, HEX.accent1, HEX.lt1);
  s.addNotes(NOTES[10]);

  // ================================================================ 12. conclusion
  pres.addSection({ title: "Conclusion" });
  s = pres.addSlide({ masterName: "CLOSING_DARK", sectionTitle: "Conclusion" });
  kicker(s, "11  ·  CONCLUSION", true);
  s.addText("Behaviour, not signatures", { placeholder: "title" });
  const conc = [
    [fa.FaCheckCircle, "Learns normal for every user and device - no attack labels needed"],
    [fa.FaCheckCircle, "Catches attacks early with about one alert a day, each explained"],
    [fa.FaCheckCircle, "Reads real Linux, Windows and proxy logs and runs as a working console"],
    [fa.FaCheckCircle, "Machine learning detects; a local language model explains"],
  ];
  for (let i = 0; i < conc.length; i++) {
    const y = 2.0 + i * 0.85;
    s.addImage({ data: await icon(conc[i][0], HEX.accent1), x: MX, y: y + 0.05, w: 0.42, h: 0.42, objectName: "Check " + (i + 1),
      altText: "check" });
    T(s, conc[i][1], { x: MX + 0.65, y, w: 7.4, h: 0.55, fontSize: 18, color: C.background1, valign: "middle" });
  }
  s.addShape(pres.shapes.OVAL, { x: 9.3, y: 2.0, w: 3.4, h: 3.4, fill: { color: HEX.accent1 }, line: { type: "none" },
    objectName: "Thanks circle" });
  T(s, "Thank you", { x: 9.3, y: 3.1, w: 3.4, h: 0.65, fontSize: 30, bold: true, color: C.text2, align: "center",
    fontFace: "Arial" });
  T(s, "Questions?", { x: 9.3, y: 3.8, w: 3.4, h: 0.5, fontSize: 18, color: C.text2, align: "center" });
  T(s, "Amaan Saify  ·  Tarun Jadhav  ·  Supervisor: Dr. Rathnakar Achary  ·  Alliance University, Bengaluru",
    { x: MX, y: 6.6, w: W - 2 * MX, h: 0.35, fontSize: 12, color: C.background2, objectName: "Closing footer" });
  s.addNotes(NOTES[11]);

  await pres.writeFile({ fileName: OUT });
  await applyTheme(OUT, THEME);
  console.log("wrote", OUT);
})().catch((e) => { console.error(e); process.exit(1); });
