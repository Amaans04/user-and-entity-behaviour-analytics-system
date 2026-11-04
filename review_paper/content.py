"""Text of the review paper.

Citations are written as {key} or {key1,key2}; build_review.py numbers them in
order of first appearance and builds the reference list from REFS.
Block types: ("h1", text) ("h2", text) ("p", text) ("bullets", [(label, text), ...])
("table", caption, header_row, rows, column_widths_in_dxa)
"""

TITLE = ("A Review of User and Entity Behaviour Analytics for Insider Threat Detection: "
         "Detection Models, Evaluation Practice and the Security Operations Centre")
AUTHORS = "Amaan Saify, Tarun S Jhadav"
SUPERVISOR = "Supervised by Dr. Rathnakar Achary"

ABSTRACT = (
    "User and Entity Behaviour Analytics (UEBA) looks for compromised accounts, malicious insiders and lateral "
    "movement by learning how users and devices normally behave and flagging departures from that baseline. Insiders "
    "use valid credentials and permitted actions, so signature-based tools see little of what they do. This paper "
    "reviews thirteen recent studies: nine that propose or evaluate detection and triage methods, and four that "
    "examine how analysts in Security Operations Centres (SOCs) handle the alerts such methods produce. After "
    "introducing the methods by technique (clustering, autoencoders, sequence models, graph models and contextual "
    "triage), the review compares them across four problems that cut through all of them: where the behavioural "
    "baseline comes from, what is profiled and at what granularity, how much labelled data is assumed, and how a "
    "score becomes an alert an analyst can act on. The comparison shows that headline results are hard to compare "
    "because data sets, label budgets and metrics differ from paper to paper; that the strongest benchmark figures "
    "depend on labels that deployments rarely have; and that a detector can rank events almost perfectly while "
    "producing an alert stream that is nearly all false alarms. The SOC studies locate the practical limit in alert "
    "volume, missing context and uninterpretable scores. Open problems include baseline poisoning, joint profiling "
    "of users and devices, and evaluation with working analysts."
)
KEYWORDS = ("user and entity behaviour analytics; insider threat detection; anomaly detection; autoencoder; "
            "graph neural network; security operations centre; false positives; explainability")

BODY = [
    # ------------------------------------------------------------------ 1
    ("h1", "1. Introduction"),
    ("p", "Most data breaches involve a human element such as stolen credentials, misuse of privilege or error "
          "{verizon}, and insider incidents are among the most expensive that organisations face {ponemon}. They are "
          "also among the hardest to detect. An insider, or an attacker who has taken over an insider's account, logs "
          "in with valid credentials and opens files that account is allowed to open. No exploit runs and no "
          "signature matches, so detection based on known indicators of compromise has little to work with "
          "{landauer}."),
    ("p", "User and Entity Behaviour Analytics takes a different route. It learns a profile of normal behaviour for "
          "each user and each entity (a workstation, server or other device) from historical logs, and reports "
          "activity that departs from it {landauer,cui}. The attack does not need to be known in advance. Recent work "
          "has applied fuzzy clustering {cui}, deep autoencoders {fuentes,zhu}, recurrent sequence models "
          "{villarreal}, graph convolutional networks {li,cai} and temporal graph models {king} to the problem, most "
          "often evaluated on the synthetic CERT insider threat data sets {cert}."),
    ("p", "Detection is only half of the story. A separate line of research studies what happens once an alert "
          "reaches a SOC. Analysts report that the great majority of alarms are not actionable {alahmadi}. Alert "
          "quality is shaped by rule tuning long before any learning is applied {vermeer}. Junior analysts often "
          "triage without a structured process {kersten}, and many do not understand or trust the scores that "
          "machine-learning tools give them {oesch}. Systems that automate part of the triage have appeared in "
          "response {vanede}. Reviews of UEBA usually cover the first literature and ignore the second. We read them "
          "together, because a detector's value in practice is set by whether its alerts get acted on."),
    ("p", "Section 2 gives background on UEBA, its data sets and its metrics. Section 3 introduces the nine detection "
          "and triage studies, grouped by technique. Sections 4 to 7 compare them across four problems: the source and "
          "stability of the baseline, what is profiled, the supervision assumed, and the path from score to alert. "
          "Section 8 brings in the four SOC studies and asks what they imply for the detectors. Section 9 tabulates the "
          "comparison, Section 10 lists open research gaps and Section 11 concludes."),

    # ------------------------------------------------------------------ 2
    ("h1", "2. Background"),
    ("h2", "2.1 Insider threats and the UEBA approach"),
    ("p", "An insider threat is a risk posed by someone with legitimate access: an employee copying data before they "
          "leave, an administrator sabotaging systems, or an outside attacker using a stolen account. UEBA grew out of "
          "user behaviour analytics by adding entities such as hosts and network devices to the things being "
          "profiled {cui}. It rests on one assumption: most users follow similar routines over long periods, so a "
          "baseline can be learned and current behaviour compared against it {landauer}. Typical signals are logon "
          "times and hosts, file and removable-media activity, e-mail, web browsing and authentication between "
          "machines."),
    ("h2", "2.2 Unsupervised anomaly detection"),
    ("p", "Labelled insider attacks are scarce, so most UEBA systems learn without labels or with very few. Isolation "
          "forests separate outliers using few random splits {iforest}. The local outlier factor compares the density "
          "around a point with that around its neighbours {lof}. Autoencoders learn to compress and reproduce normal "
          "data {hinton}, and inputs they reconstruct badly score as anomalous. LSTM networks {lstm} learn which event "
          "should come next; graph neural networks {gcn} learn from the links between users or hosts. All of these "
          "learn the baseline from data assumed to be mostly benign, so which data is used, and how old it is, matters "
          "a great deal."),
    ("h2", "2.3 Benchmark data sets"),
    ("p", "Real behaviour logs are personal data and are rarely released {landauer}. The CMU CERT insider threat test "
          "data sets {cert} fill the gap with synthetic logs of a simulated organisation, covering logons, removable "
          "devices, files, e-mail and web traffic, with injected insider scenarios. Release r4.2 simulates 1,000 "
          "employees of whom 70 are malicious; r6.2 simulates 4,000 employees with five malicious insiders {li}. The "
          "Los Alamos (LANL) data set {lanl} is real: about 1.6 billion authentication, process and network events "
          "from 58 days of an enterprise network, with labelled red-team activity {king}. NSL-KDD {nslkdd} is still "
          "used, although it holds network connection records rather than user behaviour."),
    ("h2", "2.4 Metrics and the base-rate problem"),
    ("p", "Papers report accuracy, F1, true and false positive rates, the area under the ROC curve (AUC) or the equal "
          "error rate. With malicious activity a tiny fraction of the whole, these figures can mislead. Axelsson "
          "showed that when attacks are rare, even a very small false positive rate yields far more false alarms than "
          "true ones {axelsson}. Accuracy is dominated by the benign class, and AUC measures ranking, not workload. "
          "Precision, or false alerts per day, answers the question an analyst actually has. Few papers report it."),

    # ------------------------------------------------------------------ 3
    ("h1", "3. Detection and Triage Approaches"),
    ("p", "This section introduces each method briefly. The critical comparison follows in Sections 4 to 7."),
    ("h2", "3.1 Similarity and clustering baselines"),
    ("p", "Landauer et al. {landauer} release CLUE-LDS, real logs from a cloud file-sharing platform with more than "
          "5,000 users over more than five years, anonymised so that user, action, time and context survive. Their "
          "detector compares each user's daily event-type counts with learned profiles and retrains when behaviour "
          "changes. They simulate account hijacking by swapping the identifiers of similar users. At the chosen "
          "setting it reaches a true positive rate of 65% at a false positive rate of 4.6%, under two false alarms a day."),
    ("p", "Cui et al. {cui} target a different weakness: clustering methods that place each sample in a single group "
          "and judge it only against that group. Their MAD-FPC model gives every entity fuzzy membership in several "
          "clusters. Behaviour is weighted by behaviour frequency-inverse entity frequency (BF-IEF), which works much "
          "like TF-IDF and boosts rare actions, and particle swarm optimisation searches for the centroids. An entity's "
          "anomaly factor is computed across all its clusters and thresholded with a box-plot rule. On NSL-KDD the "
          "method reaches an F1 of 0.93."),
    ("h2", "3.2 Reconstruction models"),
    ("p", "Fuentes et al. {fuentes} apply deep autoencoders to the logs of a financial institution, embedding text "
          "fields such as process information with Doc2Vec {doc2vec} alongside numeric features. Training records "
          "are those the bank's filters had already cleared, and the authors treat them as possibly contaminated "
          "rather than clean. Per-feature reconstruction residuals show which fields drove each alert. Zhu et al. "
          "{zhu} take the autoencoder in another direction. AUTH builds separate models for time features and "
          "event-frequency features, each an adversarial autoencoder {aae} with a temporal convolutional network and "
          "an LSTM in the encoder. Adversarial training pulls the latent space towards a normal distribution. On CERT "
          "it reaches an AUC of 0.932 with no labels at all."),
    ("p", "The two papers share a model family but little else. Fuentes et al. accept a weaker evaluation (they had "
          "too few labelled anomalies to compute standard metrics) in exchange for real data and an explanation "
          "attached to every alert. Zhu et al. obtain a clean benchmark number on synthetic data, and their alerts come "
          "with no explanation at all."),
    ("h2", "3.3 Sequence models"),
    ("p", "Villarreal-Vasquez et al. {villarreal} start from the observation that insiders hide attack steps among "
          "valid actions, and that detectors lose track of order beyond a certain sequence length. LADOHD trains "
          "LSTMs {lstm} on endpoint detection and response (EDR) events and judges each event against the sequence "
          "that preceded it. On 38.9 million events from 30 machines over 20 days, which include a four-day insider "
          "attack, it reaches a true positive rate of 97.29% at a false positive rate of 0.38%. LSTMs also ranked "
          "expected events in variable-length sequences better than hidden Markov models."),
    ("h2", "3.4 Graph models"),
    ("p", "Three studies use graphs, and each builds a different one. Li et al. {li} connect users. DD-GCN fuses "
          "original relationships with feature similarity, learns embeddings from both structures with attention, "
          "and reports accuracies of about 98.21% on CERT r4.2 and 98.65% on r6.2 with 60% of nodes labelled. Cai et "
          "al. {cai} connect activities. LAN models the order of activities in each sequence and, by graph "
          "structure learning, links between activities in different sequences; a hybrid loss mixes self-supervision "
          "from normal activities with supervision from abnormal ones. It detects threats in real time and beats nine "
          "baselines by at least 9.92% (r4.2) and 6.35% (r5.2) in AUC. King and Huang {king} connect hosts. EULER "
          "treats lateral movement, a stage of the MITRE ATT&CK framework {mitre}, as unlikely new edges in a "
          "sequence of authentication graphs. A graph network stacked on a recurrent encoder, distributed across "
          "machines, reaches an AUC of about 0.99 on LANL."),
    ("h2", "3.5 Contextual triage"),
    ("p", "Van Ede et al. {vanede} work downstream of detection, on the events existing detectors raise. DEEPCASE "
          "learns the context preceding each event with attention, clusters events with similar context, and asks "
          "analysts to label a few per cluster; the labels then spread to the rest. On 10.5 million events from 20 "
          "organisations collected over five months, it filters 86.72% of events automatically and cuts manual "
          "workload by 90.53%, while underestimating risk in fewer than 0.001% of cases."),

    # ------------------------------------------------------------------ 4
    ("h1", "4. Where the Baseline Comes From"),
    ("p", "Every method in Section 3 learns normal behaviour from data, so its results are only as credible as that "
          "data. The reviewed studies fall into three groups, and each has a different blind spot."),
    ("p", "DD-GCN, LAN and AUTH are evaluated on CERT {li,cai,zhu}. CERT is public and labelled, which makes it the "
          "only setting where several methods can be compared at all. It is also synthetic. Landauer et al. "
          "{landauer} argue that simulated users are scripts that repeat similar actions, so false alarm rates "
          "measured on synthetic logs are likely to be too low. Their own real data shows a second problem that CERT "
          "does not capture: users' patterns drift over five years as systems and habits change. High accuracy on "
          "CERT therefore tells us that a method separates the injected scenarios from a regular simulated "
          "background. It says much less about how often the method would raise false alarms on a real, messier "
          "workforce."),
    ("p", "Fuentes et al., Villarreal-Vasquez et al. and van Ede et al. use real data from a bank, a 30-machine "
          "commercial network and 20 organisations respectively {fuentes,villarreal,vanede}. Their findings are more "
          "convincing as evidence of real-world behaviour, but none of the data can be released, so no other method "
          "can be tested on it. LANL {lanl}, used by EULER, is the exception: real and public, though limited to "
          "host-level events."),
    ("p", "Cui et al. {cui} sit apart. NSL-KDD holds network connection records labelled with attack classes, not "
          "user behaviour. A supervised random forest in their own comparison reaches an average F1 of 0.91, close "
          "to the 0.93 of MAD-FPC. The data set is easy to separate even without behavioural modelling. The F1 "
          "figure is therefore weak evidence about insider detection, even though the method's ideas, multi-cluster "
          "membership and rare-behaviour weighting, transfer well to UEBA."),
    ("p", "How the baseline is kept current is a separate question. Landauer et al. retrain whenever behaviour "
          "changes, on 6.8% of days. The other detectors are trained once on a fixed split. Fuentes et al. are the only "
          "authors who say outright that their training data is probably contaminated. Everyone else implicitly "
          "assumes a clean baseline. This leaves a tension the literature has not resolved. Retraining handles drift, "
          "but it also gives a patient insider a way in: behave a little more unusually each week and the baseline "
          "will follow. Zhu et al. {zhu} list deliberate manipulation of the model as future work. None of the "
          "reviewed studies tests a slow-poisoning attack, and none tests a defence against one."),

    # ------------------------------------------------------------------ 5
    ("h1", "5. What Is Profiled, and at What Granularity"),
    ("p", "The 'E' in UEBA is honoured less often than the name suggests. DD-GCN and AUTH profile users {li,zhu}. "
          "LADOHD profiles endpoint event streams {villarreal}, and EULER profiles hosts and the links between them "
          "{king}. Only MAD-FPC and the autoencoder of Fuentes et al. model users and entities together {cui,fuentes}. "
          "Real insider cases cross that line all the time. Data theft involves a person, the machine they use and "
          "the removable device they plug in, so a detector that sees only one of these can miss the pattern that "
          "connects them."),
    ("p", "The three graph studies show the same split from another angle. DD-GCN links users to users, LAN links "
          "activities to activities, and EULER links hosts to hosts. Each finds that relationships carry signal that "
          "isolated features miss. No study combines the three graphs, although an attacker moving from a "
          "compromised account to new hosts would leave traces in all of them. MAD-FPC's fuzzy membership {cui} "
          "offers a cheaper form of the same idea, comparing an entity with several peer groups at once, without "
          "labels or a learned graph."),
    ("p", "Granularity pulls in two directions. Cai et al. {cai} argue that flagging a whole user or a whole day "
          "leaves analysts to search thousands of activities, and they move detection down to single activities in "
          "real time. LADOHD likewise classifies individual events. Finer decisions cut investigation effort per "
          "alert, but they also multiply the number of decisions a detector makes, and with it the number of chances "
          "to be wrong. Section 7 shows where that leads."),

    # ------------------------------------------------------------------ 6
    ("h1", "6. How Much Supervision Is Assumed"),
    ("p", "The reviewed methods span a wide range of supervision. The detectors of Landauer et al., Cui et al., "
          "Fuentes et al., Zhu et al., Villarreal-Vasquez et al. and King and Huang use no attack labels for "
          "training {landauer,cui,fuentes,zhu,villarreal,king}. LAN adds a supervised term for labelled abnormal "
          "activities {cai}. DD-GCN is semi-supervised, and its accuracy rises with the share of labelled nodes, "
          "reaching about 98% at 60% {li}. DEEPCASE needs analysts to label a sample from each cluster {vanede}."),
    ("p", "The headline numbers line up with this spectrum, which should make the reader cautious. The highest "
          "figures on CERT come from the methods that use the most labels. Labelling 60% of users is not a realistic "
          "budget for a security team that, by definition, does not know who its insiders are. The figures also "
          "resist direct comparison. DD-GCN reports accuracy on r4.2 and r6.2, LAN reports relative AUC gains on r4.2 "
          "and r5.2, and AUTH reports AUC and equal error rate on CERT. Different releases, metrics and label budgets "
          "mean that Table 1 cannot be read as a ranking. The CERT studies share no common protocol, and that gap is one of "
          "the findings of this review."),
    ("p", "The way out may be the analyst rather than the data set. DEEPCASE shows that a few analyst decisions per "
          "cluster can be reused across millions of events {vanede}. Cai et al. reach the same idea from the other "
          "side, naming an interactive labelling framework as their next step because collecting abnormal labels is "
          "costly {cai}. A detector that starts unsupervised and improves from the analyst decisions it already "
          "receives would fit how SOCs work. None of the detection papers evaluates one."),

    # ------------------------------------------------------------------ 7
    ("h1", "7. From Score to Alert"),
    ("h2", "7.1 Ranking quality is not alert quality"),
    ("p", "EULER gives the clearest example in this review {king}. Its models reach an AUC of about 0.99 and detect "
          "86-90% of malicious authentications at a false positive rate near 0.5%. Precision is only about 0.005 to "
          "0.007. Legitimate authentications so outnumber the 518 malicious edges that more than 99% of alerts are "
          "false. This is the base-rate effect Axelsson described {axelsson}, and it applies to every method here. "
          "LADOHD's false positive rate of 0.38% {villarreal} looks small. Yet an organisation logging a million "
          "events a day would face about 3,800 false events daily at that rate."),
    ("p", "Landauer et al. are the only detection authors to report false alarms per day {landauer}. Their detector "
          "scores user-days rather than events, which keeps the count below two a day, but its true positive rate is only "
          "65%. Read side by side, the two studies show the trade-off that Section 5 anticipated. Event-level "
          "detection finds more and pinpoints it better, at a cost in volume that AUC hides. Coarser units keep "
          "volume manageable but miss more. Reporting precision, or alerts per day, would let readers see where a "
          "method sits on this curve. Requiring several independent signals to agree before alerting is one way to "
          "move along it."),
    ("h2", "7.2 Triage after detection"),
    ("p", "DEEPCASE attacks the volume problem after the fact, removing most events from the analyst's queue "
          "{vanede}. It complements the detectors, since it takes existing alerts as input and needs no system-level "
          "information. Yet no reviewed study connects a UEBA detector to a triage stage like this and measures the "
          "result end to end. Grouping related alerts into a single case per user or incident, which DEEPCASE does by "
          "context, is also absent from every detector."),
    ("h2", "7.3 Explanation"),
    ("p", "Two of the nine methods explain their output. Fuentes et al. {fuentes} report which features an "
          "autoencoder failed to reconstruct, an explanation built into the score. DEEPCASE {vanede} shows the events "
          "that formed the context of a decision. The sequence and graph models {villarreal,li,cai,zhu,king} return a "
          "score for a user, activity or edge, and nothing else. Graph models are a particular case. The structure "
          "that gives them their accuracy is also what makes their decisions hard to explain to an analyst."),

    # ------------------------------------------------------------------ 8
    ("h1", "8. The Analyst's View"),
    ("p", "The four SOC studies were not written about UEBA, but their findings bear directly on the detectors above."),
    ("p", "Alahmadi et al. {alahmadi} surveyed 20 SOC practitioners and interviewed 21. Practitioners confirmed high "
          "false positive rates, manual validation and burnout. The authors found, though, that most so-called false "
          "positives are benign triggers. The alarm is technically correct, but the behaviour is legitimate in that "
          "organisation. For UEBA this is close to a definition of the problem: an anomaly detector flags unusual "
          "behaviour, and much unusual behaviour is legitimate. Precision measured against labels would count every "
          "such alert as a false positive, even when the detector did exactly what it was built to do. The authors' "
          "REACT model asks for alarms that are Reliable, Explainable, Analytical, Contextual and Transferable. By "
          "that standard, the seven of the nine reviewed methods that return a bare score fall short."),
    ("p", "Vermeer et al. {vermeer} interviewed 17 professionals about how network detection rules are written and "
          "managed. Rule specificity and the number of alerts and false positives a rule produces dominate those "
          "decisions. The authors criticise work that filters noisy alerts after the fact, arguing that it treats "
          "the symptom. This sits uneasily with DEEPCASE {vanede}, which is exactly such a filter, and an effective "
          "one. The two positions can be reconciled. Vermeer et al. are right that a detector should control its "
          "own alert volume through thresholds, weights and suppression, and a triage stage can then deal with the "
          "remainder. For UEBA, the lesson is that volume control belongs inside the detector design, not only in a "
          "later stage."),
    ("p", "Kersten et al. {kersten} gave ten tier-1 analysts a four-stage process for gathering evidence about an "
          "alert. Analysts who followed it were about 2.5 times more likely to reach a correct assessment, and the "
          "benefit was largest for alerts tied to real attacks. Oesch et al. {oesch} watched six US Navy analysts use "
          "two machine-learning tools on a cyber range. The analysts had no clear mental model of how scores were "
          "produced, mistrusted or misused them, and reached false conclusions at rates of 0.57 and 0.28 with the two "
          "tools. Experience and education did not predict performance. Between them, the two studies suggest that "
          "what accompanies an alert (its evidence, its context, a path for investigating it) affects decisions as "
          "much as the score does. None of the detection papers in this review evaluates its alerts with analysts, "
          "so this effect is unmeasured for every one of them."),

    # ------------------------------------------------------------------ 9
    ("h1", "9. Comparative Analysis"),
    ("p", "Table 1 summarises the detection and triage approaches. As Section 6 argues, the reported outcomes use "
          "different data, label budgets and metrics, and should not be read as a ranking. Table 2 summarises the SOC "
          "studies and their implications for UEBA design."),
    ("table", "Table 1. Comparative summary of UEBA and insider threat detection approaches.",
     ("Approach", "Data", "Profiles / labels", "Key reported outcome", "Limitation noted"),
     [
         ("Adaptive similarity detector, CLUE-LDS {landauer}", "Real cloud logs, 5,000+ users, 5+ years",
          "Users; unsupervised", "TPR 65% at FPR 4.6%; under 2 false alarms per day",
          "Single source; simulated hijacking; no explanation"),
         ("MAD-FPC fuzzy PSO clustering {cui}", "NSL-KDD", "Users and entities; unsupervised",
          "Accuracy 0.92, F1 0.93 (random forest 0.91)", "Network data, not behaviour logs; static; unexplained"),
         ("Deep autoencoder with Doc2Vec {fuentes}", "Real bank logs, numeric and text",
          "Users and entities; unsupervised", "Detects real and synthetic anomalies; per-feature explanations",
          "Too few labels for standard metrics; private data"),
         ("AUTH adversarial autoencoder {zhu}", "CERT", "Users; unsupervised", "AUC 0.932; EER 0.146",
          "No explanation or ranking"),
         ("LADOHD LSTM {villarreal}", "EDR, 38.9 M events, 30 hosts", "Endpoints; unsupervised",
          "TPR 97.29% at FPR 0.38%", "One organisation, one source; unexplained"),
         ("DD-GCN {li}", "CERT r4.2, r6.2", "Users; semi-supervised", "Accuracy 98.21% / 98.65%; F1 about 93%",
          "Needs 60% labelled nodes; no explanation"),
         ("LAN graph structure learning {cai}", "CERT r4.2, r5.2", "Activities; hybrid supervision",
          "AUC at least 9.92% / 6.35% above 9 baselines (real time)", "Needs abnormal labels; no explanation"),
         ("EULER temporal graph {king}", "LANL, 1.6 B events", "Hosts; unsupervised",
          "AUC about 0.99; TPR 86-90% at FPR about 0.5%", "Precision about 0.006; no explanation"),
         ("DEEPCASE {vanede}", "10.5 M events, 20 organisations", "Alerts; semi-supervised",
          "Workload reduced by 90.53%; under 0.001% risk underestimated", "Needs analyst labels; works on existing alerts"),
     ], [1900, 1700, 1500, 2300, 2100]),
    ("table", "Table 2. Summary of SOC practice studies and their implications for UEBA design.",
     ("Study", "Method", "Principal finding", "Implication for UEBA"),
     [
         ("{alahmadi}", "Survey (n = 20) and interviews (n = 21)",
          "Most false positives are benign triggers; alarms lack reliability, explanation and context",
          "Report benign triggers separately; attach explanation and context to every alert"),
         ("{vermeer}", "Interviews with 17 professionals",
          "Rule specificity and alert volume drive rule management; downstream filtering treats the symptom",
          "Control alert volume inside the detector, not only by later filtering"),
         ("{kersten}", "Experiment with 10 tier-1 analysts",
          "A structured four-stage process makes accurate assessment about 2.5 times more likely",
          "Present alerts with structured evidence and a clear investigation path"),
         ("{oesch}", "In-situ study, 6 analysts, 2 tools",
          "Analysts lack a mental model of ML scores; false conclusion rates 0.28-0.57",
          "Scores must be interpretable; design and test with analysts"),
     ], [1100, 2100, 3300, 3000]),

    # ------------------------------------------------------------------ 10
    ("h1", "10. Challenges and Research Gaps"),
    ("p", "The comparison points to the following open problems."),
    ("bullets", [
        ("A shared evaluation protocol", "CERT studies use different releases, label budgets and metrics "
         "{li,cai,zhu}, and studies on real data cannot be reproduced {fuentes,villarreal}. A common protocol on public "
         "data, ideally including real logs such as CLUE-LDS {landauer}, would make results comparable."),
        ("Operational metrics", "Precision and alerts per day should be reported next to AUC, since near-perfect AUC "
         "can coincide with precision below 1% {king,axelsson}. Benign triggers should be counted separately from "
         "false positives {alahmadi}."),
        ("Realistic label budgets", "The strongest results use labelled users or activities {li,cai}. Methods that "
         "begin unsupervised and learn from a small stream of analyst decisions {vanede} are missing among the "
         "detectors."),
        ("Joint profiling", "Few detectors model users and devices together {cui,fuentes}, and no study combines "
         "user, activity and host graphs {li,cai,king}."),
        ("Baseline poisoning", "Baselines must adapt to drift {landauer}, but adaptation opens a path for slow "
         "manipulation that no reviewed study tests {zhu}."),
        ("Volume control and corroboration", "Detectors output a single score. Requiring agreement between "
         "independent signals before alerting, ranking alerts by risk and grouping them into cases {vanede} are rarely "
         "studied, and never together."),
        ("Explanation", "Seven of nine methods return an unexplained score, against clear evidence that analysts "
         "need explanation and context {alahmadi,kersten,oesch}."),
        ("Evaluation with analysts", "No detection paper tests its alerts with working analysts, and no SOC study "
         "evaluates a UEBA detector {alahmadi,vermeer,kersten,oesch}."),
    ]),

    # ------------------------------------------------------------------ 11
    ("h1", "11. Conclusion"),
    ("p", "UEBA research has moved from clustering {cui} and adaptive similarity {landauer} to autoencoders "
          "{fuentes,zhu}, LSTMs {villarreal} and graph models {li,cai,king}, and benchmark accuracy is now high. The "
          "comparison in this review qualifies that progress. Benchmark results come mostly from synthetic data, under "
          "label budgets that real teams do not have, and are reported with metrics that cannot be compared across "
          "papers. A detector can rank events almost perfectly and still send analysts an alert stream that is more "
          "than 99% false {king}. The useful ingredients exist separately: adaptive baselines {landauer}, joint "
          "profiling of users and entities {cui}, built-in explanation {fuentes} and analyst-driven triage {vanede}. "
          "No reviewed system brings them together."),
    ("p", "The SOC studies explain why that matters. Analysts are limited by alert volume, missing context and "
          "scores they cannot interpret {alahmadi,vermeer,kersten,oesch}, not by the last point of AUC. We suggest that "
          "UEBA work should report precision and alerts per day; evaluate on real or realistic data under a shared "
          "protocol; profile users and devices together; protect adaptive baselines against slow poisoning; control "
          "alert volume inside the detector; and explain each alert in terms an analyst can check. The largest gap is "
          "the simplest to state: detectors are not yet tested with the people who have to act on their alerts."),
]

DECLARATION = ("The authors declare that they have no known competing financial interests or personal relationships "
               "that could have appeared to influence the work reported in this paper.")

# Reference style follows the template paper: authors. title. venue volume, pages (year).
REFS = {
    "verizon": "Verizon Business. 2025 Data Breach Investigations Report. Verizon (2025). "
               "https://www.verizon.com/business/resources/reports/dbir/",
    "ponemon": "Ponemon Institute, DTEX Systems. 2025 Cost of Insider Risks Global Report (2025).",
    "landauer": "M. Landauer, F. Skopik, G. Höld, M. Wurzenberger. A user and entity behavior analytics log data set "
                "for anomaly detection in cloud computing. Proc. IEEE International Conference on Big Data, "
                "4285–4294 (2022). doi:10.1109/BigData55660.2022.10020672",
    "cui": "J. Cui, G. Zhang, Z. Chen, N. Yu. Multi-homed abnormal behavior detection algorithm based on fuzzy "
           "particle swarm cluster in user and entity behavior analytics. Scientific Reports 12, 22349 (2022). "
           "doi:10.1038/s41598-022-26142-w",
    "fuentes": "J. Fuentes, I. Ortega-Fernández, N.M. Villanueva, M. Sestelo. Cybersecurity threat detection based on "
               "a UEBA framework using deep autoencoders. AIMS Mathematics 10(10), 23496–23517 (2025). "
               "doi:10.3934/math.20251043",
    "zhu": "X. Zhu, J. Dong, J. Qi, Z. Zhou, Z. Dong, Y. Sun, M. Wang. AUTH: An adversarial autoencoder based "
           "unsupervised insider threat detection scheme for multisource logs. IEEE Transactions on Industrial "
           "Informatics 20(9), 10954–10965 (2024). doi:10.1109/TII.2024.3393491",
    "villarreal": "M. Villarreal-Vasquez, G. Modelo-Howard, S. Dube, B. Bhargava. Hunting for insider threats using "
                  "LSTM-based anomaly detection. IEEE Transactions on Dependable and Secure Computing 20(1), 451–462 "
                  "(2023). doi:10.1109/TDSC.2021.3135639",
    "li": "X. Li, X. Li, J. Jia, L. Li, J. Yuan, Y. Gao, S. Yu. A high accuracy and adaptive anomaly detection model "
          "with dual-domain graph convolutional network for insider threat detection. IEEE Transactions on "
          "Information Forensics and Security 18, 1638–1652 (2023). doi:10.1109/TIFS.2023.3245413",
    "cai": "X. Cai, Y. Wang, S. Xu, H. Li, Y. Zhang, Z. Liu, X. Yuan. LAN: Learning adaptive neighbors for real-time "
           "insider threat detection. IEEE Transactions on Information Forensics and Security 19, 10157–10172 "
           "(2024). doi:10.1109/TIFS.2024.3488527",
    "king": "I.J. King, H.H. Huang. Euler: Detecting network lateral movement via scalable temporal link prediction. "
            "Proc. Network and Distributed System Security Symposium (NDSS) (2022). Extended version: ACM "
            "Transactions on Privacy and Security 26(3) (2023). doi:10.1145/3588771",
    "cert": "B. Lindauer. Insider Threat Test Dataset. Carnegie Mellon University, Software Engineering Institute "
            "(2020). doi:10.1184/R1/12841247.v1",
    "alahmadi": "B.A. Alahmadi, L. Axon, I. Martinovic. 99% false positives: A qualitative study of SOC analysts' "
                "perspectives on security alarms. Proc. 31st USENIX Security Symposium, 2783–2800 (2022).",
    "vermeer": "M. Vermeer, N. Kadenko, M. van Eeten, C. Gañán, S. Parkin. Alert alchemy: SOC workflows and decisions "
               "in the management of NIDS rules. Proc. ACM SIGSAC Conference on Computer and Communications "
               "Security (CCS), 2770–2784 (2023). doi:10.1145/3576915.3616581",
    "kersten": "L. Kersten, T. Mulders, E. Zambon, C. Snijders, L. Allodi. 'Give me structure': Synthesis and "
               "evaluation of a (network) threat analysis process supporting tier 1 investigations in a security "
               "operation center. Proc. 19th Symposium on Usable Privacy and Security (SOUPS), 97–111 (2023).",
    "oesch": "S. Oesch, R. Bridges, J. Smith, J. Beaver, J. Goodall, K. Huffer, C. Miles, D. Scofield. An assessment "
             "of the usability of machine learning based tools for the security operations center. Proc. IEEE "
             "International Conferences on iThings, GreenCom, CPSCom, SmartData and Cybermatics, 634–641 (2020). "
             "doi:10.1109/iThings-GreenCom-CPSCom-SmartData-Cybermatics50389.2020.00111",
    "vanede": "T. van Ede, H. Aghakhani, N. Spahn, R. Bortolameotti, M. Cova, A. Continella, M. van Steen, A. Peter, "
              "C. Kruegel, G. Vigna. DEEPCASE: Semi-supervised contextual analysis of security events. Proc. IEEE "
              "Symposium on Security and Privacy (SP), 522–539 (2022). doi:10.1109/SP46214.2022.9833671",
    "iforest": "F.T. Liu, K.M. Ting, Z.-H. Zhou. Isolation forest. Proc. 8th IEEE International Conference on Data "
               "Mining (ICDM), 413–422 (2008). doi:10.1109/ICDM.2008.17",
    "lof": "M.M. Breunig, H.-P. Kriegel, R.T. Ng, J. Sander. LOF: Identifying density-based local outliers. Proc. ACM "
           "SIGMOD International Conference on Management of Data, 93–104 (2000). doi:10.1145/335191.335388",
    "hinton": "G.E. Hinton, R.R. Salakhutdinov. Reducing the dimensionality of data with neural networks. Science "
              "313(5786), 504–507 (2006).",
    "lstm": "S. Hochreiter, J. Schmidhuber. Long short-term memory. Neural Computation 9(8), 1735–1780 (1997).",
    "gcn": "T.N. Kipf, M. Welling. Semi-supervised classification with graph convolutional networks. Proc. "
           "International Conference on Learning Representations (ICLR) (2017).",
    "lanl": "A.D. Kent. Comprehensive, Multi-Source Cyber-Security Events. Los Alamos National Laboratory (2015). "
            "doi:10.17021/1179829",
    "nslkdd": "M. Tavallaee, E. Bagheri, W. Lu, A.A. Ghorbani. A detailed analysis of the KDD CUP 99 data set. Proc. "
              "IEEE Symposium on Computational Intelligence for Security and Defense Applications (CISDA), 1–6 (2009). doi:10.1109/CISDA.2009.5356528",
    "axelsson": "S. Axelsson. The base-rate fallacy and the difficulty of intrusion detection. ACM Transactions on "
                "Information and System Security 3(3), 186–205 (2000). doi:10.1145/357830.357849",
    "doc2vec": "Q. Le, T. Mikolov. Distributed representations of sentences and documents. Proc. 31st International "
               "Conference on Machine Learning (ICML), 1188–1196 (2014).",
    "aae": "A. Makhzani, J. Shlens, N. Jaitly, I. Goodfellow, B. Frey. Adversarial autoencoders. arXiv:1511.05644 "
           "(2015).",
    "mitre": "The MITRE Corporation. MITRE ATT&CK. https://attack.mitre.org/ (accessed 2026).",
}
