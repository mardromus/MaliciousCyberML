// Sections 1-4: Introduction, Literature Review, Methodology, Implementation.
const L = require("./lib");
const { P, H1, H2, H3, bullets, numbered, equation, figure, table } = L;

const pct = (x, d = 1) => (100 * x).toFixed(d) + "%";
const n = (x) => Number(x).toLocaleString("en-US");

module.exports = function sectionsA(R, ctx) {
  const c = R.cleaning;
  const malRaw = c.raw_counts.malicious_pure;
  const benRaw = c.raw_counts.powershell_benign_dataset;
  const malU = c.final_counts.malicious_pure;
  const benU = c.final_counts.powershell_benign_dataset;
  const malFam = c.skeleton_groups.malicious_pure;
  const dupShare = (malRaw - malU - c.label_conflicts_removed / 2) / malRaw;
  const out = [];
  const add = (...b) => b.forEach((x) => (Array.isArray(x) ? out.push(...x) : out.push(x)));

  // ------------------------------------------------------------------ 1
  add(H1("1. Introduction"));
  add(H2("1.1 Background"));
  add(P("PowerShell is the command shell and scripting language that Microsoft builds on top of the .NET runtime and installs by default on every supported version of Windows. System administrators rely on it for configuration management, Active Directory maintenance, patch deployment and cloud automation. The properties that make it valuable to them—direct access to .NET classes and Win32 APIs, the ability to run code held only in memory, and built-in remote management—are exactly what an intruder needs after gaining a foothold on a machine. A single PowerShell line can fetch a second-stage payload over HTTP, load it through reflection and run it without ever writing an executable file to disk. Security vendors call this style of intrusion “living off the land” or “fileless” because the attacker uses tools that are already trusted on the host [@wueest2017]."));
  add(P("The problem is not new, but it has not gone away. Symantec reported in 2016 that 95.4% of the PowerShell scripts submitted to the Blue Coat sandbox it analysed were malicious [@wueest2016]. MITRE ATT&CK catalogues the behaviour as sub-technique T1059.001 [@mitre_t1059], and the 2025 Threat Detection Report published by Red Canary again listed Command and Scripting Interpreter as the most frequently observed ATT&CK technique across its customer base, for the sixth year in a row [@redcanary2025]. Ransomware affiliates, commodity loaders and state-sponsored groups all use it."));
  add(P("Simply removing PowerShell is not a workable defence. In June 2022 the United States National Security Agency (NSA) and Cybersecurity and Infrastructure Security Agency (CISA), together with the national cyber security centres of New Zealand and the United Kingdom, published joint guidance that advises organisations to *keep* PowerShell and instead configure and monitor it properly [@nsa2022]. Their recommendations—Script Block Logging, the Antimalware Scan Interface (AMSI), constrained language mode and transcription—produce large volumes of high-quality telemetry. What they do not provide is a decision: someone, or something, still has to look at each captured script and judge whether it is hostile, quickly enough to act before the attacker reaches their objective."));

  add(H2("1.2 Relevance in Today’s Threat Landscape"));
  add(P("Three trends make an AI-assisted detection and response capability for PowerShell especially timely:"));
  add(bullets([
    "**Obfuscation is cheap and automated.** Freely available tools such as Invoke-Obfuscation can rewrite one malicious command into thousands of syntactically different but functionally equivalent forms [@bohannon2016]. Static signatures that match exact strings break almost immediately, while statistical models can generalise across such variants [@bohannon2017].",
    "**Security teams are overloaded.** Endpoint detection products raise far more alerts than analysts can triage, and alert fatigue is a recognised cause of missed intrusions [@hassan2019]. A model that assigns a calibrated risk score lets low-risk events be handled automatically and puts the analyst’s attention where it is needed.",
    "**Generative AI is entering both sides of the contest.** Large language models (LLMs) have been evaluated for de-obfuscating real malware droppers [@patsakis2024] and for explaining why a PowerShell script is malicious [@wang2026]. Classical ML detectors remain the fast, cheap first line that decides which events deserve such deeper (and costlier) analysis.",
  ]));
  add(P("Finally, current incident-response guidance treats detection and response as part of continuous risk management rather than a separate activity [@nist2025]. A system that links a detector to a documented, auditable response playbook therefore matches how organisations are now expected to operate."));

  add(H2("1.3 Problem Statement"));
  add(P("Given the text of a PowerShell script block captured on a Windows endpoint, the system must (i) estimate the probability that the script is malicious, with a false-positive rate low enough for production use, and (ii) choose a proportionate response automatically—ranging from simply logging the event to terminating the process and isolating the host—while keeping a human analyst in control of the most disruptive actions. The solution must work on static text alone, because executing unknown scripts to observe them is slow and risky, and it must be evaluated in a way that reflects how it would perform on scripts it has never seen."));

  add(H2("1.4 Objectives"));
  add(numbered([
    "Audit a public, labelled PowerShell corpus for duplicates, label conflicts and spurious artefacts before any model is trained.",
    "Engineer features that capture both lexical patterns and behavioural intent, and map the behavioural features to MITRE ATT&CK techniques.",
    "Train and compare several classifiers using an evaluation protocol that prevents near-duplicate scripts from leaking between training and test data.",
    "Design a policy-driven response engine that converts a risk score into graded actions and records every decision in an audit log.",
    "Measure detection quality, response outcomes and processing latency, and discuss the limitations of the approach.",
  ], "obj"));

  add(H2("1.5 Contributions"));
  add(P("The work makes the following contributions:"));
  add(bullets([
    `A data-quality audit of the MPSD corpus [@fang2021] showing that ${pct(dupShare, 0)} of its malicious files are exact duplicates, that ${c.label_conflicts_removed} files appear under both labels, and that UTF-8 byte-order marks occur only in benign-derived files—an artefact that a model could exploit as a shortcut.`,
    `A family-aware evaluation protocol based on structural “skeleton” hashing, which groups the ${n(malU)} unique malicious scripts into ${n(malFam)} families and keeps each family entirely within one cross-validation fold.`,
    "A hybrid detector that combines character n-gram TF-IDF features with 33 interpretable statistical and ATT&CK-aligned behavioural indicators, compared against single-view baselines.",
    "A tiered automated response engine that consumes Windows Event ID 4104 records, attaches ATT&CK technique context, plans containment actions and requires analyst approval before host isolation, together with an end-to-end replay experiment that measures its outcomes and latency.",
  ]));

  add(H2("1.6 Organisation of the Report"));
  add(P("Section 2 reviews published work on PowerShell attack detection, de-obfuscation, evaluation pitfalls and automated response. Section 3 explains the methodology: data audit, pre-processing, features, models, evaluation protocol and response policy. Section 4 describes the implementation. Section 5 presents and discusses the results, and Section 6 concludes with directions for future work."));

  // ------------------------------------------------------------------ 2
  add(H1("2. Literature Review"));
  add(H2("2.1 PowerShell Telemetry and the Threat Context"));
  add(P("Since PowerShell 5.0, Microsoft has shipped several features aimed at defenders. Script Block Logging records the text of every script block that the PowerShell engine compiles in the Microsoft-Windows-PowerShell/Operational event log under Event ID 4104 [@ms_logging]. Because logging happens at compile time, code that is generated at run time—for example, a string decoded from Base64 and then passed to Invoke-Expression—is also logged in its decoded form. AMSI goes one step further: it lets any registered anti-malware engine inspect a script buffer immediately before it runs and block it [@ms_amsi]. The joint NSA/CISA guidance recommends enabling both, along with transcription and constrained language mode [@nsa2022]. On the analysis side, the ATT&CK knowledge base gives defenders a common vocabulary for describing adversary behaviour in terms of tactics and techniques [@strom2018], which this project uses to label what a detected script is trying to do."));
  add(P("Industry reporting has documented PowerShell abuse for almost a decade. Symantec’s 2016 white paper described how attackers use it for downloading payloads, lateral movement and reconnaissance [@wueest2016], and its 2017 special report placed it at the centre of fileless attack techniques [@wueest2017]. More recent threat-detection reports continue to rank script interpreters at the top of observed techniques [@redcanary2025]."));

  add(H2("2.2 Obfuscation and De-obfuscation"));
  add(P("Bohannon’s Invoke-Obfuscation framework showed how easily PowerShell can be disguised at the token, string, encoding and launcher levels [@bohannon2016]. In response, Bohannon and Holmes built Revoke-Obfuscation, which extracts around 4,000 features from the abstract syntax tree (AST) of a script and uses a linear model to decide whether it is obfuscated; to build it they assembled a corpus of 408,000 scripts, about 7,000 of which were manually reviewed and labelled [@bohannon2017]. Their work demonstrated that *statistical* properties of code are far more robust than string signatures."));
  add(P("A second line of work tries to undo obfuscation before detection. PowerDrive is a multi-stage static and dynamic de-obfuscator that progressively peels off obfuscation layers and was used to analyse thousands of real attacks [@ugarte2019]. Li et al. proposed a light-weight, AST-subtree-based de-obfuscation method combined with semantic-aware detection [@li2019], later extended into a more general framework by Xiong et al. [@xiong2022]. PowerDP first predicts which obfuscation types were applied to a command, then uses targeted regular-expression replacement to recover the original content, and finally profiles the command’s behaviour with multi-label classifiers [@tsai2023]. PowerPeeler moves to the dynamic side, de-obfuscating at the instruction level while the script executes [@li2024]. Most recently, Patsakis et al. tested LLMs on PowerShell droppers from the Emotet campaign and found that GPT-4 could extract the hidden download URLs in 69.56% of cases [@patsakis2024]. The common lesson is that de-obfuscation improves detection but adds cost and complexity; in-engine telemetry such as Event ID 4104 already provides a partially de-obfuscated view at no extra cost, which is the input this project uses."));

  add(H2("2.3 Machine-Learning Detectors for PowerShell"));
  add(P("Hendler, Kels and Rubin carried out one of the first large studies, training character-level convolutional and recurrent networks and a natural-language-processing (NLP) baseline on 66,388 commands collected by Microsoft [@hendler2018]. Their best detector was an ensemble of the NLP model and a CNN, because each caught commands the other missed. In follow-up work they used data collected through AMSI and pre-trained contextual embeddings on a large corpus of unlabelled scripts; the best model detected nearly 90% of malicious code at a false-positive rate below 0.1% [@hendler2020]. Microsoft described the deployment of such deep models in its Defender products in a 2019 blog post [@ms_blog2019]."));
  add(P("Other studies explore different representations. Rusak et al. learned embeddings of AST nodes to classify malicious scripts by family [@rusak2018]. Song et al. compared token-based and AST-based feature sets with both machine-learning and deep-learning models and reported detection rates of about 98% after feature optimisation [@song2021]. Mimura and Tajiri showed that word-embedding representations of scripts support purely static detection [@mimura2021]. Fang et al. combined FastText embeddings with textual, token and AST-node features and a random forest; they reported 98.93% accuracy on original scripts and 97.76% on a harder set in which malicious code is inserted into benign scripts, and released the dataset (MPSD) used in this case study [@fang2021]. Beyond PowerShell, Saxe and Berlin’s eXpose demonstrated that character-level models work well on short security strings such as URLs, file paths and registry keys [@saxe2017]. Broader surveys of ML for malware analysis are given by Ucci et al. [@ucci2019] and Gibert et al. [@gibert2020]. The newest direction uses LLMs not only to classify scripts but also to point to the responsible lines of code and explain the verdict in natural language [@wang2026]."));

  add(H2("2.4 Pitfalls in Evaluating Security Machine Learning"));
  add(P("High headline accuracy does not guarantee real-world value. Sommer and Paxson argued early on that intrusion detection differs from typical ML tasks because errors are costly, data are scarce and the environment keeps changing [@sommer2010]. Arp et al. catalogued ten common pitfalls—including sampling bias, data snooping, spurious correlations and inappropriate performance measures—and confirmed in a study of 30 papers from top security venues that these pitfalls are widespread [@arp2022]. Pendlebury et al. showed that random train/test splits which ignore time and class ratios can make malware classifiers look much better than they are [@pendlebury2019]. For imbalanced problems, Saito and Rehmsmeier recommend complementing ROC curves with precision-oriented measures [@saito2015]. These findings directly shaped the evaluation design in Section 3.7: duplicated and near-duplicated scripts are a form of data snooping, and the byte-order-mark artefact is a textbook spurious correlation."));

  add(H2("2.5 Automated Incident Response"));
  add(P("Security orchestration, automation and response (SOAR) platforms connect detection tools to response actions through playbooks. Islam et al. reviewed the academic and grey literature on security orchestration and identified automation of repetitive response tasks and integration of heterogeneous tools as its main goals [@islam2019]. NoDoze reduced false alarms by ranking alerts with the help of provenance graphs [@hassan2019], and Hassan et al. later showed that linking endpoint alerts into provenance graphs tagged with ATT&CK tactics and techniques reduces false alarms and helps analysts triage [@hassan2020]. NIST SP 800-61 Rev. 3 organises incident-response recommendations around the six Functions of the NIST Cybersecurity Framework 2.0 (Govern, Identify, Protect, Detect, Respond and Recover), treating response as part of overall cybersecurity risk management [@nist2025]."));

  add(H2("2.6 Summary and Research Gap"));
  const lit = table("Summary of representative related work", ["Work", "Approach", "Reported outcome", "Gap relevant to this study"], [
    ["Hendler et al. 2018 [@hendler2018]", "Char-level CNN/RNN + NLP ensemble", "High recall at very low FPR on 66k commands", "Proprietary data; detection only"],
    ["Hendler et al. 2020 [@hendler2020]", "AMSI data, contextual embeddings", "≈90% TPR at <0.1% FPR", "Needs large unlabelled corpus and GPU training"],
    ["Bohannon & Holmes 2017 [@bohannon2017]", "AST features + linear model", "Robust obfuscation detection", "Detects obfuscation, not maliciousness"],
    ["Li et al. 2019 [@li2019]", "AST-subtree de-obfuscation + semantic detection", "Recovers obfuscated scripts", "Extra processing stage; no response"],
    ["Song et al. 2021 [@song2021]", "Token/AST feature optimisation", "≈98% detection", "Random splits; no duplicate analysis"],
    ["Fang et al. 2021 [@fang2021]", "FastText + hybrid features + RF", "98.93% / 97.76% accuracy", "Duplicates in data not addressed"],
    ["Tsai et al. 2023 [@tsai2023]", "Obfuscation-type prediction + regex de-obfuscation", "98.11% recovery over 15 types", "Command-level; no response"],
    ["Wang et al. 2026 [@wang2026]", "LLM classification + explanation", "Human-readable explanations", "Cost and latency of LLM inference"],
  ], [2.2, 2.4, 2.2, 2.6]);
  add(P(`Table ${lit.n} summarises representative studies. Taken together, the literature shows that (a) ML detectors can reach high accuracy on PowerShell, (b) obfuscation-robust features matter more than exact strings, and (c) evaluation choices can strongly inflate reported numbers. Three gaps remain. First, few studies audit their datasets for duplicates and artefacts before reporting results. Second, most work ends at a classification score, leaving open how that score should drive a safe, automated response. Third, response decisions are rarely tied to interpretable evidence such as ATT&CK techniques that an analyst can verify. This case study addresses all three.`));
  add(lit.blocks);

  // ------------------------------------------------------------------ 3
  add(H1("3. Methodology"));
  add(H2("3.1 Overview"));
  const fig1 = figure(ctx.fig("fig1_architecture.png"), "End-to-end architecture of the proposed detection and automated response system", 6.3);
  add(P(`Figure ${fig1.n} shows the overall design. Script-block text arrives from endpoint telemetry (Event ID 4104 or an AMSI buffer). It is cleaned and normalised, converted into two complementary feature views, and scored by a trained model. A policy engine converts the risk score and the behavioural evidence into a response tier, and the corresponding actions are executed (or, in this study, simulated) and logged. Analyst decisions feed back into the labelled data used for periodic retraining. The offline part of the pipeline—data audit, model training, cross-validation and threshold selection—is described in Sections 3.3 to 3.7; the online response logic is described in Section 3.8.`));
  add(fig1.blocks);

  add(H2("3.2 Threat Model and Assumptions"));
  add(P("The adversary has already obtained code execution on a Windows endpoint (for example, through a phishing attachment or a stolen credential) and uses PowerShell to download tools, inject code, establish persistence, dump credentials or open a command channel. The adversary may obfuscate scripts, rename variables and embed malicious code inside otherwise legitimate scripts. We assume Script Block Logging or AMSI is enabled and that its output reaches the analysis service; an attempt to disable logging is itself treated as a suspicious signal (the defence-evasion indicator group in Section 3.5.3). Out of scope are attacks that never invoke PowerShell and white-box adversarial attacks in which the attacker can query or inspect the model to craft evasive inputs [@goodfellow2015]; the latter are discussed as a limitation."));

  add(H2("3.3 Dataset and Data-Quality Audit"));
  add(P(`The study uses the public MPSD corpus released by Fang et al. [@fang2021]. It contains ${n(malRaw)} malicious scripts (malicious_pure), ${n(benRaw)} benign scripts (powershell_benign_dataset) and ${n(4202)} “mixed” malicious scripts, each created by inserting one malicious script into one benign script. The malicious samples cover download cradles, shellcode loaders, reverse shells, credential-theft tools and persistence scripts; the benign samples are administration scripts and modules collected from public repositories.`));
  add(P("Before training, the corpus was audited using three checks recommended by the security-ML literature [@arp2022]:"));
  add(numbered([
    `**Exact duplicates.** Each script was hashed (SHA-256) after collapsing whitespace and lowercasing. Only ${n(malU)} of the ${n(malRaw)} malicious files were unique: ${pct(dupShare, 1)} of them were exact copies of another file. Duplicates were removed so that each distinct script is counted once.`,
    `**Label conflicts.** ${c.label_conflicts_removed} files, sharing ${c.label_conflicts_removed / 2} distinct script contents, appeared in both the malicious and the benign folders. Since their true label cannot be known, all of them were discarded.`,
    "**Spurious artefacts.** None of the malicious files started with a UTF-8 byte-order mark (BOM), whereas about 35% of the benign files did. A model could learn “BOM means benign”—a rule that an attacker could exploit trivially by adding three bytes. The BOM is therefore stripped from every file before any feature is computed.",
  ], "steps"));
  add(P(`Removing exact duplicates is not sufficient, because many malicious scripts are produced by the same generator and differ only in variable names, numeric constants (such as port numbers or shellcode bytes) or whitespace. To capture these near-duplicates, each script is reduced to a structural *skeleton*: it is lowercased, every variable name is replaced by a placeholder, every decimal or hexadecimal literal is replaced by 0, and all whitespace is removed. Scripts with the same skeleton hash form one *family*. The ${n(malU)} unique malicious scripts collapse into only ${n(malFam)} families, while the ${n(benU)} benign scripts form ${n(c.skeleton_groups.powershell_benign_dataset)} families. Figure 2 visualises the effect of each cleaning step.`));
  add(figure(ctx.fig("fig2_dataset.png"), "Effect of the data-quality audit: raw files, unique scripts after exact de-duplication, and structural families", 5.6).blocks);

  add(H2("3.4 Pre-processing and Normalisation"));
  add(P("Each script is decoded as UTF-8 (or UTF-16 if a UTF-16 BOM is present), the BOM is removed and the text is truncated to 200,000 characters to bound processing time for a small number of very large files. For the lexical view, the text is then normalised in two ways that do not change the meaning of PowerShell code: it is converted to lower case, because PowerShell keywords, cmdlets and variable names are case-insensitive, and backtick characters are removed, because PowerShell ignores the backtick escape inside identifiers (so that I`nv`oke-Ex`pression and Invoke-Expression are the same command). Runs of spaces and tabs are collapsed. These steps cheaply undo two of the most common token-level obfuscations without any execution. The statistical features in Section 3.5.2 are computed on the raw text, because properties such as case ratio and backtick density are themselves informative."));

  add(H2("3.5 Feature Engineering"));
  add(P("Two complementary views of each script are built. The lexical view captures *how the code is written*; the statistical and behavioural view captures *what the code does* and *what it looks like overall*. Using both follows the observation by Hendler et al. that models built on different representations make different mistakes [@hendler2018]."));
  add(H3("3.5.1 Character n-gram TF-IDF"));
  add(P("The normalised text is split into overlapping character sequences of length 3, 4 and 5. Character n-grams are robust to renamed variables and partly split strings, and they do not require a PowerShell parser. Each n-gram t in script d is weighted with sub-linear term frequency and smoothed inverse document frequency [@salton1988]:"));
  add(equation("w_{t,d} = (1 + ln tf_{t,d}) × [ ln((1 + N) / (1 + df_{t})) + 1 ]", "1"));
  add(P("where tf_{t,d} is the number of times t occurs in d, N is the number of training scripts and df_{t} is the number of training scripts containing t. Each script vector is then scaled to unit Euclidean length. Only n-grams that occur in at least three training scripts are kept, and the vocabulary is capped at the 50,000 most frequent n-grams. The vectoriser is fitted inside each cross-validation fold on training data only, so that document frequencies never include test scripts."));
  add(H3("3.5.2 Statistical Features"));
  add(P("Twenty-four numeric features describe the overall shape of a script: its length and number of lines (log-scaled), mean and maximum line length, the proportions of alphabetic, digit, upper-case, whitespace and special characters, the densities of backticks, plus signs (used for string concatenation), quotes and braces, the length of the longest token, the number of Base64-like blobs (runs of 80 or more Base64 characters), the number of URLs and IPv4 addresses, the density and number of distinct variables, the proportion of comment lines, the number of function definitions, the number of comment-based help keywords (.SYNOPSIS, .EXAMPLE and so on) and whether a param() block is present. Character-level Shannon entropy [@shannon1948] is included because encoded or compressed payloads have higher entropy than hand-written code:"));
  add(equation("H(d) = − Σ_{c} p_{c} log_{2} p_{c}", "2"));
  add(P("where p_{c} is the relative frequency of character c in the script. The documentation-related features reflect a simple observation: legitimate administrative scripts are usually written to be maintained by others and therefore contain help blocks, parameters and functions, whereas attack scripts are usually short, dense and undocumented."));
  add(H3("3.5.3 Behavioural Indicator Groups Mapped to ATT&CK"));
  const ind = table("Behavioural indicator groups, example patterns and the ATT&CK technique each group supports", ["Indicator group", "Example patterns (normalised text)", "ATT&CK technique"], [
    ["Dynamic execution", "invoke-expression, iex, invoke-command, [scriptblock]::create", "T1059.001 PowerShell"],
    ["Download cradle", "downloadstring, downloadfile, net.webclient, invoke-webrequest, bitstransfer", "T1105 Ingress Tool Transfer"],
    ["Encoding / compression", "frombase64string, -encodedcommand, -bxor, gzipstream, [char]NN", "T1027 Obfuscated Files or Information"],
    ["Win32 API / injection", "virtualalloc, createthread, writeprocessmemory, dllimport, kernel32", "T1055 Process Injection"],
    ["Defence evasion", "-windowstyle hidden, -noprofile, bypass, amsi, set-mppreference", "T1562.001 Disable or Modify Tools"],
    ["Persistence", "schtasks, register-scheduledtask, currentversion\\run, new-service", "T1053.005 Scheduled Task"],
    ["Credential access", "mimikatz, sekurlsa, lsass, logonpasswords", "T1003.001 LSASS Memory"],
    ["Raw sockets", "net.sockets, tcpclient, tcplistener, .getstream()", "T1095 Non-Application Layer Protocol"],
    ["Reflection", "reflection.assembly, ::load(, add-type", "T1620 Reflective Code Loading"],
  ], [2.0, 4.2, 2.6]);
  add(P(`Nine further features count matches for groups of regular expressions that capture common attacker behaviours (Table ${ind.n}). Each count is log-scaled. Grouping patterns by tactic rather than using each keyword as a separate feature keeps the feature space small and stable, and—more importantly—gives the response engine human-readable evidence: when a script is blocked, the alert can state, for example, that it combined a download cradle (T1105) with dynamic execution (T1059.001). In total the statistical and behavioural view has 33 features.`));
  add(ind.blocks);

  add(H2("3.6 Classification Models and Justification"));
  add(P("Four single-view models and one ensemble were compared. All are implemented with scikit-learn [@pedregosa2011] and use class weighting to compensate for the roughly 1:2.3 malicious-to-benign ratio after cleaning."));
  add(bullets([
    "**Char TF-IDF + Logistic Regression (LR).** A linear model is the natural choice for very high-dimensional sparse text features: it trains in seconds, is hard to over-fit with L2 regularisation (inverse strength C = 10 here) and its coefficients can be read directly as the n-grams that push a script towards one class. The model estimates P(malicious | x) = σ(w·x + b), where σ is the logistic function.",
    "**Hand-crafted + LR.** The same linear model on the 33 standardised statistical and behavioural features. It serves as an interpretable baseline that shows how much can be achieved with a few dozen features.",
    "**Hand-crafted + Random Forest (RF).** An ensemble of 300 decision trees trained on bootstrap samples with random feature subsets [@breiman2001]. RFs capture non-linear interactions (for example, “high entropy *and* no comments”), need no feature scaling and are robust to outliers such as extremely long scripts.",
    "**Hand-crafted + Histogram Gradient Boosting (HGB).** A boosted-tree model that bins features into histograms for speed, in the style of LightGBM [@ke2017]. It is included as the strongest conventional tabular learner.",
    "**Soft-voting ensemble.** The final detector averages the malicious-class probabilities of the lexical model and the behavioural RF:",
  ]));
  add(equation("p_{ens}(x) = ½ · p_{LR}^{TF-IDF}(x) + ½ · p_{RF}^{hand}(x)", "3"));
  add(P("The two members look at different evidence—surface character patterns versus overall shape and behaviour—so their errors are only weakly correlated, and averaging them reduces variance. Equal weights were chosen deliberately instead of tuning them on the test folds, to avoid optimistic bias. Deep neural networks were not used: on a corpus of about six thousand unique scripts, published results [@song2021, fang2021] suggest that well-engineered classical models are competitive, and they are cheaper to train, faster at inference and easier to explain to an analyst."));

  add(H2("3.7 Evaluation Protocol"));
  add(P("All models are evaluated with five-fold cross-validation [@kohavi1995] under two protocols:"));
  add(bullets([
    "**Naive protocol (for comparison only).** The raw corpus, including duplicates, is split with ordinary stratified five-fold cross-validation. This mimics a common practice in the literature and shows how optimistic it can be.",
    "**Family-aware protocol (main results).** The de-duplicated corpus is split with stratified *group* five-fold cross-validation, using the skeleton family from Section 3.3 as the group. Every member of a family falls into the same fold, so a model is never tested on a script whose near-twin it saw during training.",
  ]));
  add(P("Predictions from the held-out folds are pooled (out-of-fold predictions) so that every script is scored exactly once by a model that did not see it. With TP, FP, TN and FN denoting true/false positives/negatives and malicious as the positive class, the following measures are reported:"));
  add(equation("Precision = TP / (TP + FP),   Recall (TPR) = TP / (TP + FN)", "4"));
  add(equation("F1 = 2 · Precision · Recall / (Precision + Recall),   FPR = FP / (FP + TN)", "5"));
  add(P("together with accuracy, the area under the ROC curve (ROC-AUC) and the true-positive rate at a fixed false-positive rate of 1% (TPR@1%FPR). The last measure matters most operationally: in a large organisation, even a 1% false-positive rate on benign scripts can generate many alerts per day, so the detection rate *at a low, fixed FPR* is a more honest summary than accuracy [@saito2015, arp2022]."));
  add(P("A third experiment stresses the detector with the mixed subset of MPSD, in which malicious code is hidden inside a benign script. To avoid leakage, a mixed sample is scored only by the model of the fold that did *not* contain its malicious parent script; the benign host script may have been seen during training as benign, which makes the test deliberately harder. Mixed samples whose malicious parent could not be identified from the file name were excluded."));

  add(H2("3.8 Automated Response Design"));
  add(P("Detection alone does not stop an attack. The response engine turns the ensemble’s score p and the set G of behavioural indicator groups that fired into one of four tiers. The tiers follow the principle of proportionality: cheap, reversible actions are automated freely; disruptive actions require stronger evidence; and the most disruptive action—isolating a host from the network—additionally requires analyst approval."));
  const pol = table("Response policy: tiers, triggering conditions and automated actions", ["Tier", "Condition", "Automated actions", "Human role"], [
    ["ALLOW", "p < 0.30", "Record verdict in SIEM", "None"],
    ["ALERT", "0.30 ≤ p < 0.70", "Record verdict; open SOC ticket with score, ATT&CK techniques and defanged IOCs", "Analyst triages"],
    ["CONTAIN", "p ≥ 0.70", "All of the above, plus terminate the PowerShell process, quarantine the script file, block its SHA-256 hash, block extracted URLs/IPs", "Analyst reviews and may roll back"],
    ["ISOLATE", "p ≥ 0.95 and G contains injection, credential access or reflection", "All of the above, plus network isolation of the host", "Approval required before isolation"],
  ], [1.55, 2.3, 3.75, 1.8]);
  add(pol.blocks);
  add(P(`Table ${pol.n} lists the policy. The thresholds were set *a priori* from the operational meaning of each tier rather than tuned on test data; Section 5 reports how the out-of-fold scores fall relative to them. Every decision—score, tier, techniques, indicators of compromise (IOCs) and actions—is written as one JSON line to an append-only audit log. IOCs are “defanged” (for example, http becomes hxxp and dots become [.]) so that logs cannot be clicked accidentally. By default the engine runs in *dry-run* mode, marking every action as “simulated”; this mirrors how SOAR playbooks are normally validated in production before they are allowed to act [@islam2019].`));

  add(H2("3.9 Ethical and Safety Considerations"));
  add(P("All malicious samples were handled purely as text and were never executed. The dataset is downloaded from its public source at run time and is not redistributed in the project repository. IOCs are defanged in all outputs and are omitted from this report. The response engine cannot perform any real action unless dry-run mode is explicitly switched off, and host isolation always requires human approval. These choices follow the principle that an automated defence should fail safe and remain accountable to people [@nist2025]."));

  // ------------------------------------------------------------------ 4
  add(H1("4. Implementation Details"));
  add(H2("4.1 Development Environment"));
  const env = table("Software and hardware environment", ["Component", "Version / specification"], [
    ["Language", "Python 3.13"],
    ["Machine-learning library", "scikit-learn 1.9 [@pedregosa2011]"],
    ["Data handling", "pandas 3.0, NumPy 2.5"],
    ["Plotting", "Matplotlib 3.11"],
    ["Testing", "pytest (7 unit tests)"],
    ["Hardware", "4 virtual CPU cores, 15 GB RAM, no GPU (Linux container)"],
    ["Dataset", "MPSD, public GitHub repository das-lab/mpsd [@fang2021]"],
  ], [3, 6]);
  add(env.blocks);

  add(H2("4.2 Software Architecture"));
  const mods = table("Main modules of the implementation", ["Module", "Responsibility"], [
    ["psdetect/data.py", "Reads scripts, strips BOMs, removes exact duplicates and label conflicts, computes skeleton families"],
    ["psdetect/features.py", "Normalisation, 24 statistical features, 9 ATT&CK-aligned indicator groups, scikit-learn transformer"],
    ["psdetect/models.py", "Model pipelines (TF-IDF + LR, hand-crafted + LR/RF/HGB) and the soft-voting ensemble"],
    ["psdetect/response.py", "Response engine: scoring, tier selection, ATT&CK mapping, IOC extraction and defanging, action planning, audit log"],
    ["experiments/run_experiments.py", "Naive and family-aware cross-validation, mixed-script stress test, feature importance"],
    ["experiments/simulate_response.py", "Replays a held-out fold as Event ID 4104 records through the response engine"],
    ["experiments/make_figures.py", "Generates all figures in this report from the saved results"],
    ["tests/test_pipeline.py", "Unit tests for normalisation, features, family hashing, policy tiers and defanging"],
  ], [3.2, 6.0]);
  add(P(`The code is organised as a small Python package plus experiment scripts (Table ${mods.n}). Every model is a scikit-learn Pipeline that accepts raw script text, so exactly the same code path is used during cross-validation, in the response simulation and in a deployment. All random seeds are fixed (seed 42) so that every number in this report can be regenerated with three commands: fetch the data, run the experiments and build the figures.`));
  add(mods.blocks);

  add(H2("4.3 Hyper-parameters"));
  const hp = table("Model hyper-parameters", ["Model", "Key settings"], [
    ["Char TF-IDF + LR", "n-gram range 3–5 (characters), min_df = 3, max_features = 50,000, sub-linear tf; LR with C = 10, L2 penalty, class_weight = balanced, max_iter = 2,000"],
    ["Hand-crafted + LR", "Standard scaling; C = 1, class_weight = balanced"],
    ["Hand-crafted + RF", "300 trees, Gini impurity, unlimited depth, min_samples_leaf = 1, class_weight = balanced"],
    ["Hand-crafted + HGB", "300 boosting iterations, learning rate 0.08, class_weight = balanced"],
    ["Ensemble", "Equal-weight average of TF-IDF + LR and hand-crafted + RF probabilities"],
  ], [2.4, 6.6]);
  add(P(`Table ${hp.n} lists the hyper-parameters. They were fixed from common defaults and a brief sanity check, not searched exhaustively on the evaluation folds; a nested search would likely add a little performance but would also add a risk of over-fitting the small number of malicious families.`));
  add(hp.blocks);

  add(H2("4.4 Response Engine Algorithm"));
  add(P("For each incoming Event ID 4104 record, the engine performs the following steps:"));
  add(numbered([
    "Read ScriptBlockText, ScriptBlockId, Computer, ProcessId and Path from the event.",
    "Compute the ensemble probability p for the script text.",
    "Normalise the text and count matches for each indicator group; let G be the set of groups with at least one match.",
    "Select the tier: ISOLATE if p ≥ 0.95 and G contains a high-impact group; otherwise CONTAIN if p ≥ 0.70; otherwise ALERT if p ≥ 0.30; otherwise ALLOW.",
    "Map every group in G to its ATT&CK technique; for ALERT and above, extract and defang URLs and IP addresses.",
    "Build the action plan for the tier (Table 4); mark each action as simulated or executed according to the dry-run setting; flag ISOLATE for analyst approval.",
    "Measure the elapsed time, write the complete decision as one JSON line to the audit log and return it.",
  ], "alg"));

  add(H2("4.5 Deployment Path on Windows Endpoints"));
  add(P("In a real deployment, Script Block Logging is enabled through Group Policy (Administrative Templates → Windows Components → Windows PowerShell → Turn on PowerShell Script Block Logging) [@ms_logging]. Event ID 4104 records are shipped to a central collector with Windows Event Forwarding or an endpoint agent. Large scripts are split by Windows across several 4104 events that share a ScriptBlockId and carry MessageNumber and MessageTotal fields, so the collector reassembles them before scoring. The trained pipeline is serialised with joblib and served behind a small internal API; the response engine’s action stubs are then connected to the organisation’s endpoint detection and response (EDR) platform, firewall and ticketing system. Because AMSI exposes the same script text immediately before execution [@ms_amsi], the identical model could also be called from an AMSI provider to block scripts *before* they run rather than responding after the fact."));

  add(H2("4.6 Testing"));
  add(P("Seven unit tests check that normalisation folds case and backticks, that the feature vector has the expected shape and contains only finite values, that indicator groups fire on a typical download cradle but not on a documented administrative function, that two scripts differing only in variable names share a skeleton hash, that the policy produces the correct tier for given scores, that isolation is chosen only when a high-impact technique is present and is flagged for approval, and that IOC defanging works. All tests pass."));

  return out;
};
