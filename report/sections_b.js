// Sections 5-6: Results & Discussion, Conclusion.
const fs = require("fs");
const path = require("path");
const L = require("./lib");
const { P, H1, H2, H3, bullets, numbered, figure, table } = L;

const pct = (x, d = 1) => (100 * x).toFixed(d) + "%";
const f3 = (x) => Number(x).toFixed(3);
const f4 = (x) => Number(x).toFixed(4);
const n = (x) => Number(x).toLocaleString("en-US");
const ENS = "Ensemble (TF-IDF LR + RF)";
const ORDER = ["Handcrafted + LR", "Handcrafted + RF", "Handcrafted + HGB", "Char TF-IDF + LR", ENS];
const LABEL = { [ENS]: "Ensemble (TF-IDF LR + RF)" };
const lab = (m) => LABEL[m] || m;
const mean = (a) => a.reduce((x, y) => x + y, 0) / a.length;
const std = (a) => Math.sqrt(mean(a.map((x) => (x - mean(a)) ** 2)));

module.exports = function sectionsB(R, S, ctx) {
  const E = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "results/error_analysis.json")));
  const G = R.group_split;
  const N = R.naive_random_split;
  const M = R.mixed_embedded;
  const g = G[ENS];
  const tf = G["Char TF-IDF + LR"];
  const rf = G["Handcrafted + RF"];
  const hgb = G["Handcrafted + HGB"];
  const hlr = G["Handcrafted + LR"];
  const foldF1 = R.group_split_f1_per_fold[ENS];
  const out = [];
  const add = (...b) => b.forEach((x) => (Array.isArray(x) ? out.push(...x) : out.push(x)));
  const nBen = g.tn + g.fp;
  const nMal = g.tp + g.fn;

  add(H1("5. Results and Discussion"));

  // 5.1
  add(H2("5.1 Impact of the Data-Quality Audit"));
  add(P(`The audit changed the experimental picture before any model was trained. Of ${n(R.cleaning.raw_counts.malicious_pure + R.cleaning.raw_counts.powershell_benign_dataset)} raw files, ${n(R.cleaning.exact_duplicates_removed)} exact duplicates and ${R.cleaning.label_conflicts_removed} conflicting files were removed, leaving ${n(nMal)} malicious and ${n(nBen)} benign scripts. The class balance therefore shifted from roughly 1:1 in the raw corpus to about 1:${(nBen / nMal).toFixed(1)} after cleaning. More importantly, the ${n(nMal)} unique malicious scripts belong to only ${n(R.cleaning.skeleton_groups.malicious_pure)} structural families, so on average each malicious “idea” appears about ${(nMal / R.cleaning.skeleton_groups.malicious_pure).toFixed(1)} times with cosmetic changes. Any split that scatters such families across training and test folds lets a model succeed by recognising near-copies rather than by learning what makes a script malicious. Section 5.3 measures how large that effect is.`));

  // 5.2
  add(H2("5.2 Detection Performance under Family-Aware Evaluation"));
  const perf = table("Out-of-fold detection performance under family-aware five-fold cross-validation (threshold 0.5; malicious = positive class)",
    ["Model", "Acc.", "Prec.", "Recall", "F1", "ROC-AUC", "TPR @1% FPR", "FP", "FN"],
    ORDER.map((m) => [lab(m), f4(G[m].accuracy), f4(G[m].precision), f4(G[m].recall), f4(G[m].f1), f4(G[m].roc_auc), f4(G[m].tpr_at_fpr_1pct), G[m].fp, G[m].fn]),
    [3.0, 1.05, 1.05, 1.05, 1.05, 1.15, 1.2, 0.7, 0.7]);
  add(P(`Table ${perf.n} reports the main results. Every model performs well, which confirms that malicious and benign PowerShell differ substantially in both wording and behaviour. The differences between models are nevertheless informative.`));
  add(perf.blocks);
  add(bullets([
    `**Lexical features are the strongest single view.** Char TF-IDF + LR achieves the highest F1 (${f4(tf.f1)}) and ROC-AUC (${f4(tf.roc_auc)}). Character n-grams pick up fragments of API names, .NET type names and command-line switches even when they are split across strings or surrounded by unfamiliar code.`,
    `**Thirty-three interpretable features go a long way.** With only the hand-crafted view, the tree models reach F1 of ${f4(rf.f1)} (RF) and ${f4(hgb.f1)} (HGB) and the highest precision of all models (${f4(rf.precision)} and ${f4(hgb.precision)}). The linear model on the same features is clearly weaker (F1 ${f4(hlr.f1)}, ${hlr.fp} false positives), which shows that interactions between features—captured by trees but not by a linear boundary—matter.`,
    `**The ensemble trades a little recall for fewer false alarms.** At the default threshold the ensemble produces ${g.fp} false positives versus ${tf.fp} for the lexical model, at the cost of ${g.fn - tf.fn} additional false negatives, giving an almost identical F1 (${f4(g.f1)} vs ${f4(tf.f1)}). At the operating point that matters most—1% FPR—the two are virtually identical (${pct(g.tpr_at_fpr_1pct, 2)} vs ${pct(tf.tpr_at_fpr_1pct, 2)}).`,
  ]));
  add(P(`The ensemble was nonetheless kept as the detector behind the response engine for two practical reasons. First, false positives are what make automated containment expensive—each one can kill a legitimate administrator’s job—so the model with the fewest false alarms at a competitive detection rate is preferable. Second, its Random Forest member contributes behavioural evidence that the response engine can explain to an analyst more clearly than thousands of n-gram weights. Across the five folds, the ensemble’s F1 ranged from ${f3(Math.min(...foldF1))} to ${f3(Math.max(...foldF1))} (mean ${f3(mean(foldF1))}, standard deviation ${f3(std(foldF1))}); the spread comes mostly from which malicious families happen to fall into each test fold, and the result is not driven by one lucky split.`));
  const roc = figure(ctx.fig("fig3_roc.png"), "ROC curves of all models under family-aware cross-validation (logarithmic false-positive axis; the dashed line marks FPR = 1%)", 5.6);
  add(P(`Figure ${roc.n} shows the ROC curves on a logarithmic false-positive axis, which magnifies the low-FPR region that matters in practice. The lexical model and the ensemble dominate the hand-crafted models below 1% FPR, while the hand-crafted linear model falls behind across the whole range.`));
  add(roc.blocks);
  const cm = figure(ctx.fig("fig5_confusion.png"), "Confusion matrix of the ensemble (out-of-fold, threshold 0.5); percentages are per actual class", 3.4);
  add(P(`Figure ${cm.n} gives the ensemble’s confusion matrix: ${n(g.tn)} of ${n(nBen)} benign scripts (${pct(g.tn / nBen, 2)}) and ${n(g.tp)} of ${n(nMal)} malicious scripts (${pct(g.tp / nMal, 2)}) are classified correctly.`));
  add(cm.blocks);

  // 5.3
  add(H2("5.3 Effect of the Evaluation Protocol"));
  const proto = table("Naive random split on raw data versus family-aware split on cleaned data",
    ["Model", "F1\n(naive)", "F1\n(family-aware)", "TPR @ 1% FPR\n(naive)", "TPR @ 1% FPR\n(family-aware)"],
    ORDER.map((m) => [lab(m), f4(N[m].f1), f4(G[m].f1), f4(N[m].tpr_at_fpr_1pct), f4(G[m].tpr_at_fpr_1pct)]),
    [3.0, 1.4, 1.6, 1.7, 1.9]);
  const gap = ORDER.map((m) => N[m].f1 - G[m].f1);
  const fnRatio = ORDER.map((m) => (G[m].fn / (G[m].tp + G[m].fn)) / Math.max(N[m].fn / (N[m].tp + N[m].fn), 1e-9));
  const nvg = figure(ctx.fig("fig4_naive_vs_group.png"), "True-positive rate at 1% false-positive rate under the two evaluation protocols (labels show family-aware → naive)", 6.0);
  add(P(`Table ${proto.n} and Figure ${nvg.n} compare the two protocols. Under the naive protocol—duplicates kept, random folds—every model looks better: F1 rises by ${f3(Math.min(...gap))} to ${f3(Math.max(...gap))} points, and the ensemble’s TPR at 1% FPR rises from ${pct(g.tpr_at_fpr_1pct, 2)} to ${pct(N[ENS].tpr_at_fpr_1pct, 2)}. These gaps look small in absolute terms, but they hide a large relative difference in errors: the share of malicious scripts that the ensemble misses is ${fnRatio[4].toFixed(1)} times higher under the family-aware protocol than under the naive one. In other words, a naive evaluation would understate the miss rate a security team should expect on genuinely new attacks by a factor of about ${Math.round(fnRatio[4])}. This mirrors the warnings of Arp et al. [@arp2022] and Pendlebury et al. [@pendlebury2019] and suggests that results reported on MPSD with random splits, including very high accuracies, should be read with this caveat in mind.`));
  add(proto.blocks);
  add(nvg.blocks);

  // 5.4
  add(H2("5.4 Stress Test: Malicious Code Embedded in Benign Scripts"));
  const mix = table("Detection rate on mixed scripts (malicious code inserted into a benign script), scored by models that never saw the malicious parent",
    ["Model", "Detection rate (p ≥ 0.5)", "Mean risk score"],
    ORDER.map((m) => [lab(m), pct(M.detection_rate[m], 2), f3(M.mean_score[m])]),
    [3.4, 2.4, 2.0]);
  const best = ORDER.reduce((a, b) => (M.detection_rate[a] >= M.detection_rate[b] ? a : b));
  const worst = ORDER.reduce((a, b) => (M.detection_rate[a] <= M.detection_rate[b] ? a : b));
  add(P(`The mixed subset of MPSD represents a realistic evasion strategy: hiding a payload inside a long, legitimate-looking administration script. ${n(M.n_evaluated)} mixed scripts were scored (${M.n_skipped} were skipped because their malicious parent could not be identified). Table ${mix.n} shows the results. The best detection rate was obtained by ${lab(best)} (${pct(M.detection_rate[best], 2)}) and the lowest by ${lab(worst)} (${pct(M.detection_rate[worst], 2)}); the ensemble detected ${pct(M.detection_rate[ENS], 2)}.`));
  add(mix.blocks);
  add(P(`This is the most important weakness uncovered by the study: every model trained only on standalone scripts misses roughly half of the embedded payloads. The explanation follows from Section 5.5. The strongest signals are the overall *shape* of a script and, for the lexical model, its length-normalised n-gram profile. When a few lines of malicious code are buried inside hundreds of lines of neatly formatted administrative code, both views are dominated by the benign host. The simplest model, logistic regression on hand-crafted features, does best because its indicator counts add up linearly instead of being overruled by shape-based splits, as happens in the tree models.`));
  const mtPath = path.join(__dirname, "..", "results/mixed_training.json");
  if (fs.existsSync(mtPath)) {
    const MT = JSON.parse(fs.readFileSync(mtPath));
    add(H3("5.4.1 Mitigation: mixed-aware training"));
    const mt = table("Effect of adding mixed scripts to the training folds (base → mixed-aware); clean-test metrics are out-of-fold on the de-duplicated corpus",
      ["Model", "Clean F1", "Clean FPR", "Mixed detected (p ≥ 0.5)", "Mixed ≥ ALERT"],
      ORDER.map((m) => [lab(m), `${f3(G[m].f1)} → ${f3(MT.clean_test[m].f1)}`, `${pct(G[m].fpr, 2)} → ${pct(MT.clean_test[m].fpr, 2)}`,
        `${pct(M.detection_rate[m], 1)} → ${pct(MT.mixed_detection_rate[m], 1)}`, pct(MT.mixed_alert_or_higher_rate[m], 1)]),
      [2.5, 2.05, 2.25, 2.45, 1.35]);
    add(P(ctx.mitigationNarrative(MT, M, G, mt.n, mean(MT.augmented_training_samples_per_fold))));
    add(mt.blocks);
  }

  // 5.5
  add(H2("5.5 Explainability"));
  const imp = figure(ctx.fig("fig6_importance.png"), "Fourteen most important hand-crafted features of the Random Forest (mean decrease in impurity)", 5.6);
  const top = R.rf_feature_importance.slice(0, 5).map((x) => ctx.pretty(x.feature).toLowerCase());
  const rankWin = R.rf_feature_importance.findIndex((x) => x.feature === "ind_win32_api") + 1;
  add(P(`Figure ${imp.n} lists the most influential hand-crafted features of the Random Forest. The five most important are ${top.slice(0, 4).join(", ")} and ${top[4]}—all measures of the *shape* of the code rather than of particular commands. The pattern is easy to interpret: attack scripts in the corpus are usually dense one-liners or short blocks with long lines, little indentation, many special characters and long runs of digits (for example, shellcode stored as byte arrays), whereas administration scripts are spread over many short, indented lines. The first behavioural feature, the Win32 API/injection indicator group, ranks ${ctx.ordinal(rankWin)}. The dominance of shape features is a double-edged result: they are cheap and effective, but an attacker can change them simply by re-formatting the code or by wrapping it in a long benign script, which is exactly the weakness exposed in Section 5.4.`));
  add(P(`The logistic-regression model on character n-grams offers a complementary, more behavioural explanation. Among its highest positive weights are ${ctx.ngrams(R.lr_top_malicious_ngrams, ["iex", "(new-", "w-ob", ".exe", "dow"])}—fragments of the Invoke-Expression alias, of New-Object, of executable file names and of Download methods—whereas the strongest benign n-grams, such as ${ctx.ngrams(R.lr_top_benign_ngrams, [" { $", "\n} ", "name"])}, reflect neatly formatted code blocks and named parameters (here “·” marks a space and “\\n” a line break). For an analyst, the most useful explanation is the list of ATT&CK techniques that the response engine attaches to every alert (Section 5.7), because it describes *behaviour* rather than model internals. Model-agnostic attribution methods such as SHAP [@lundberg2017] could add per-script explanations in a future version.`));
  add(imp.blocks);

  // 5.6
  add(H2("5.6 Error Analysis"));
  const efp = E.false_positive;
  const efn = E.false_negative;
  add(P(`Looking at the ensemble’s ${efp.count} false positives and ${efn.count} false negatives (without reproducing their content) reveals two distinct patterns:`));
  add(bullets([
    `**False positives are long, dual-use tools.** Their median length is ${n(efp.median_length)} characters, more than twenty times that of a typical benign script, and on average ${efp.mean_indicator_groups} indicator groups fire per script (versus ${E.true_negative.mean_indicator_groups} for correctly classified benign scripts). ${pct(efp.group_presence.reflection, 0)} use reflection and ${pct(efp.group_presence.win32_api, 0)} call Win32 APIs. Inspection of their function names shows code-signing helpers, memory and logon-session inspection utilities, DLL-loading wrappers and penetration-testing modules that the dataset labels benign. Such scripts are legitimately ambiguous: the same code that an administrator uses for diagnostics is used by attackers for injection.`,
    `**False negatives look like ordinary administration.** They contain few behavioural indicators (${efn.mean_indicator_groups} groups on average; ${pct(efn.share_with_no_indicator, 0)} trigger none). Typical examples write registry values, create a scheduled task with an innocuous name, collect the user and host name, or build strings from character codes. Whether such actions are malicious depends on context—who ran them, from where, and what happened next—that is not visible in the script text alone.`,
  ]));
  add(P(`The tiered policy softens the impact of both error types. ${pct(E.false_negative_still_alerted_share, 1)} of the missed malicious scripts still score at least 0.30 and therefore raise an ALERT for an analyst rather than passing silently, while ${pct(1 - E.false_positive_contained_share, 0)} of the false positives fall below the CONTAIN threshold and only generate a ticket. Adding context from process ancestry or network telemetry, as in provenance-based triage [@hassan2019, hassan2020], is the most promising way to reduce both error types further.`));

  // 5.7
  add(H2("5.7 Automated Response Simulation"));
  const tc = S.tier_counts;
  const get = (cls, t) => (tc[cls][t] || 0);
  const resp = table("Outcome of replaying an unseen fold as Event ID 4104 records through the response engine (dry-run)",
    ["Measure", "Value"], [
      ["Training scripts (folds 1–4) / replayed events (fold 5)", `${n(S.train_size)} / ${n(S.replayed_events)}`],
      ["Replayed malicious / benign", `${n(S.replayed_malicious)} / ${n(S.replayed_benign)}`],
      ["Malicious: ALLOW / ALERT / CONTAIN / ISOLATE", `${get("malicious", "ALLOW")} / ${get("malicious", "ALERT")} / ${get("malicious", "CONTAIN")} / ${get("malicious", "ISOLATE")}`],
      ["Benign: ALLOW / ALERT / CONTAIN / ISOLATE", `${get("benign", "ALLOW")} / ${get("benign", "ALERT")} / ${get("benign", "CONTAIN")} / ${get("benign", "ISOLATE")}`],
      ["Malicious scripts contained (CONTAIN or ISOLATE)", pct(S.malicious_contained_rate, 2)],
      ["Malicious scripts at least alerted", pct(S.malicious_alerted_or_higher_rate, 2)],
      ["Benign scripts wrongly contained", pct(S.benign_contained_rate, 2)],
      ["Benign scripts sent to analyst as ALERT", pct(S.benign_alert_rate, 2)],
      ["Isolations awaiting analyst approval", n(S.isolations_pending_analyst)],
      ["Mean actions per contained event", S.mean_actions_per_contained_event.toFixed(2)],
      ["Latency per event: median / mean / 95th percentile", `${S.latency_ms.median.toFixed(1)} / ${S.latency_ms.mean.toFixed(1)} / ${S.latency_ms.p95.toFixed(1)} ms`],
      ["Throughput (single process)", `${S.throughput_events_per_s.toFixed(1)} events per second`],
    ], [5.5, 3.5]);
  add(P(`To test the complete detection-to-response loop, the ensemble was trained on four of the five family-aware folds and the fifth fold was replayed as a stream of synthetic Event ID 4104 records. Each record carried a script-block identifier, host name, user, process ID and, for 60% of events, a file path. The replay used the base ensemble trained on standalone scripts, so it measures the response loop on ordinary scripts; the embedded-code case is covered in Section 5.4. Table ${resp.n} summarises the outcome.`));
  add(resp.blocks);
  const sd = figure(ctx.fig("fig7_score_distribution.png"), "Distribution of out-of-fold ensemble risk scores for benign and malicious scripts, with the policy thresholds", 5.8);
  const tiersFig = figure(ctx.fig("fig8_response_tiers.png"), "Response tiers assigned to benign and malicious events in the replay experiment", 6.0);
  add(P(ctx.responseNarrative(S, get, sd.n, tiersFig.n)));
  const techs = Object.entries(S.attack_techniques_in_contained_events).sort((a, b) => b[1] - a[1]);
  add(P(`Every contained event carried ATT&CK context. The techniques attached most often were ${techs.slice(0, 4).map(([k, v]) => `${k} (${n(v)} events)`).join(", ")}, which matches the shellcode-loader and download-cradle families that dominate the malicious data. The median end-to-end latency of ${S.latency_ms.median.toFixed(1)} ms per event—dominated by feature extraction and scoring—means that a single process can keep up with roughly ${n(Math.round(S.throughput_events_per_s * 3600))} script blocks per hour; long scripts take longer, as the 95th percentile of ${S.latency_ms.p95.toFixed(1)} ms shows, but remain far below the time an attacker needs to move laterally.`));
  add(sd.blocks);
  add(tiersFig.blocks);

  // 5.8
  add(H2("5.8 Comparison with Published Work"));
  const cmp = table("Indicative comparison with published PowerShell detectors (datasets and protocols differ, so the figures are not directly comparable)",
    ["Study", "Data / protocol", "Reported result"], [
      ["Fang et al. 2021 [@fang2021]", "MPSD; random 5-fold CV", "Accuracy 98.93% (original), 97.76% (mixed)"],
      ["Song et al. 2021 [@song2021]", "Own corpus; token/AST features", "Detection rate ≈98%"],
      ["Hendler et al. 2020 [@hendler2020]", "AMSI data from Microsoft", "TPR ≈90% at FPR < 0.1%"],
      ["This work (ensemble)", "MPSD, de-duplicated; family-aware 5-fold CV", `Accuracy ${pct(g.accuracy, 2)}, F1 ${f4(g.f1)}, TPR ${pct(g.tpr_at_fpr_1pct, 2)} at 1% FPR`],
      ["This work (ensemble, naive split)", "MPSD raw; random 5-fold CV", `Accuracy ${pct(N[ENS].accuracy, 2)}, F1 ${f4(N[ENS].f1)}`],
    ], [3.0, 3.4, 3.4]);
  add(P(`Table ${cmp.n} places the results next to published work. On the same corpus, our accuracy under the stricter family-aware protocol (${pct(g.accuracy, 2)}) is close to the ${pct(0.9893, 2)} reported by Fang et al. with random splits, even though our models are simpler and do not use AST parsing or embeddings. Under a naive split comparable to theirs our ensemble reaches ${pct(N[ENS].accuracy, 2)}. The comparison with Hendler et al. is only indicative, because their data come from real AMSI telemetry with far more benign variety, which is the harder and more realistic setting.`));
  add(cmp.blocks);

  // 5.9
  add(H2("5.9 Limitations and Threats to Validity"));
  add(bullets([
    "**Dataset scope.** MPSD is a single public corpus with a limited number of malicious families and benign scripts drawn mainly from public repositories. Enterprise environments contain in-house scripts that may look different, so the false-positive rate should be re-measured on local data before deployment.",
    "**No temporal split.** The scripts carry no reliable timestamps, so it was not possible to train on older and test on newer attacks, as recommended by Pendlebury et al. [@pendlebury2019]. Family-aware splitting addresses near-duplicates but not concept drift.",
    "**Static view only.** The detector sees only script text. Context such as parent process, user, network connections and command-line arguments, which EDR products collect, would help with the ambiguous cases identified in Section 5.6.",
    "**Adversarial robustness.** An attacker who can query the model could search for variants that lower the score [@goodfellow2015]. Using AMSI or Event ID 4104 output (which already removes several obfuscation layers), combining lexical and behavioural evidence, and keeping thresholds conservative reduce but do not remove this risk.",
    "**Simulated response.** Actions were simulated in dry-run mode on synthetic event metadata; the real cost of terminating processes or isolating hosts in a production network was not measured.",
  ]));

  // 6
  add(H1("6. Conclusion and Future Work"));
  add(P(`This case study set out to build and evaluate an AI-based system that detects malicious PowerShell scripts and responds to them automatically, while staying honest about how well such a system really works. A careful audit of the public MPSD corpus came first and proved essential: more than half of its malicious files were duplicates, a handful of files carried contradictory labels, byte-order marks offered a spurious shortcut, and the remaining malicious scripts formed only ${n(R.cleaning.skeleton_groups.malicious_pure)} structural families. Under a family-aware evaluation that respects these facts, a lightweight ensemble of a character n-gram logistic-regression model and a Random Forest on 33 interpretable features reached an F1-score of ${f4(g.f1)}, a ROC-AUC of ${f4(g.roc_auc)} and a true-positive rate of ${pct(g.tpr_at_fpr_1pct, 2)} at a 1% false-positive rate. A naive random split would have understated the miss rate roughly ${Math.round((g.fn / (g.tp + g.fn)) / (N[ENS].fn / (N[ENS].tp + N[ENS].fn)))}-fold, which is a warning for anyone comparing published numbers. The study also exposed a clear weakness: malicious code hidden inside long benign scripts evaded models trained only on standalone samples about half of the time, because whole-script shape features are diluted by the benign host. Adding such examples to the training data raised the ensemble’s detection of embedded payloads to ${pct(ctx.MT.mixed_detection_rate[ENS], 1)}, at the cost of a small rise in false positives on ordinary scripts.`));
  add(P(`Detection was then connected to action. The tiered response engine consumes the same Event ID 4104 records that Windows already produces, attaches ATT&CK techniques and defanged indicators to every decision, and scales its response from logging to process termination, quarantine and network blocking, with host isolation held back for analyst approval. In a replay of unseen scripts it contained ${pct(S.malicious_contained_rate, 1)} of malicious events, wrongly contained ${pct(S.benign_contained_rate, 2)} of benign ones and needed a median of ${S.latency_ms.median.toFixed(1)} ms per event. These results show that explainable machine learning combined with a proportionate, auditable response policy is a practical way to defend against living-off-the-land PowerShell attacks, in line with current guidance to keep PowerShell but monitor it closely [@nsa2022, nist2025].`));
  add(P("Several extensions would strengthen the system:"));
  add(numbered([
    "Validate on enterprise telemetry and with a temporal split to measure concept drift, and add periodic retraining driven by analyst feedback.",
    "Score individual functions and script blocks separately, in addition to the whole script, so that a small malicious section cannot be diluted by a large benign host.",
    "Add AST-based features and pre-trained code embeddings [@hendler2020, fang2021] and compare them with the current features under the same family-aware protocol.",
    "Integrate the model as an AMSI provider so that high-confidence scripts are blocked before execution rather than after.",
    "Enrich decisions with process-tree and network context from EDR provenance graphs to resolve the dual-use cases that cause most errors [@hassan2020].",
    "Use a large language model as a second-stage analyst assistant that explains ALERT-tier scripts in natural language [@wang2026], keeping the fast classical model as the first-line filter.",
    "Evaluate robustness against adaptive adversaries and harden the model with adversarially augmented training data.",
  ], "future"));
  return out;
};
