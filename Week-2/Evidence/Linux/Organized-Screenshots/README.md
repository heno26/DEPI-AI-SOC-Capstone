# Linux Screenshot Evidence — Week 2 | DEPI P5

> **الدليل التوثيقي للصور (27 صورة حسب القائمة الظاهرة في Windows Explorer).** هذا الملف يشرح وظيفة كل Screenshot، ترتيبها في الـEvidence Trail، وما تثبته وما لا تثبته.
> **Evidence interpretation note:** Entries were reconstructed from the visible folder listing and terminal outputs shared during the project. The 27 individual image files have **not** been independently inspected here; verify each image against its caption before submission.

## 1. Project context & scope

**Project:** AI-Assisted SOC Automation & Full Incident Response Capstone (DEPI P5).  **Phase:** Week 2 — Linux Log Analysis, Evidence Verification, AI Review, Feedback & Grounded Detection.

الـScreenshots بتوثق رحلة الدليل من **المصدر الأصلي → التحقق من السلامة → اختيار الأحداث → Parsing → Mistral → Automated Validation → Human Review → Final Evidence Documentation → Regression / Replay**. الصور ليست بديلًا عن الـRaw Logs أو ملفات الـManifest، بل دليل بصري مساعد.

**Wazuh remains in project scope.** وجود `Evidence/Wazuh/` متوقع، ولم يُلغ من المشروع. هذا الفهرس يغطي Linux Evidence فقط، ولا يمثل إثباتًا لتكامل Wazuh الحي.

### Snapshot status

| Field | Value / caveat |
|---|---|
| Screenshots identified from folder view | **27** (file extensions hidden in Explorer) |
| Linux cases | LT-01 / LT-02 / LT-03 / LT-04 |
| LT-01 focused SSH records | **42**; 13 `Failed password` occurrences in focus |
| LT-02 | **108** original PROCTITLE records; **21** focused records |
| LT-03 | **2** identical source XML lines → **1** distinct recorded event |
| LT-04 | **2,000** source log lines → **18** focused low-risk candidates |
| Confirmed suite size previously observed | **168 passing tests** before the negation-fix phase |
| Screenshot named `177-Regression-PASS` | **Caption/name requires checking against actual screenshot**; do not report 177 as confirmed just from its filename |
| Human review and model output | Separate records; a `Corrected` review is not equivalent to AI approval |

## 2. Recommended organization (copy, never move originals)

Keep the existing folder intact at `D:\Desktop\w\Week-2\Evidence\Linux\Screenshots`. The optional organizer will make **copies** in a sibling folder:

```text
Evidence/
└── Linux/
    ├── Final-Verification/           # Existing folder: leave unchanged
    ├── Screenshots/                  # Original 27 pictures + this README
    └── Organized-Screenshots/        # Created only when --organize is run
        ├── 01-LT01-SSH-Brute-Force/
        ├── 02-LT02-Privilege-Sensitive-Commands/
        ├── 03-LT03-Bash-Reverse-Shell/
        ├── 04-LT04-Low-Risk-Linux-Startup/
        ├── 05-Cross-Case-Final-Verification/
        ├── 06-Feedback-and-Validation-Upgrades/
        ├── Screenshot-Inventory.csv
        ├── Screenshot-Integrity-Manifest.json
        └── README.md
```

**Chronology:** within each case, use Source → Inspection/Selection → Parser → AI → Human Review → Final Verification. Naming order in Explorer is alphabetical and **not** chronological. Numbered IDs below define the documentation sequence; the ID numbers are catalog identifiers, not event IDs.

## 3. Screenshot-by-screenshot catalog | شرح كل سكرينة

### LT-01 — OpenSSH brute-force / repeated authentication failures

**01. `LT01-Evidence-Selection-Parser-PASS`** — `PASS`  
- **الشرح:** اختيار 42 سطر SSH من مصدر Loghub، والتحقق من قراءة الـParser وارتباط المراجع بالسجلات؛ شملت العينة 13 Failed password.  
- **Instructor caption (EN):** Evidence selection and parser check for 42 SSH log records, including 13 failed-password records.

**02. `LT01-Mistral-SSH-Analysis`** — `AI OUTPUT`  
- **الشرح:** تشغيل Mistral محليًا لتحليل محاولات SSH الفاشلة واستخراج ملخص ومؤشرات وتعليمات التحقيق؛ التقرير يحتاج Validation وHuman Review.  
- **Instructor caption (EN):** Local Mistral triage of repeated SSH authentication failures, prior to final human acceptance.

**03. `LT01-Automated-Validation-6Flags-1`** — `DIAGNOSTIC`  
- **الشرح:** الجزء الأول من تحذيرات التحقق الآلي لتحليل SSH؛ يوضح أن مخرجات Mistral احتاجت مراجعة وليس أن الهجوم نجح.  
- **Instructor caption (EN):** First capture of six automated validation review flags in the SSH case.

**04. `LT01-Automated-Validation-6Flags-2`** — `DIAGNOSTIC`  
- **الشرح:** تكملة الـ6 Flags؛ تستخدم لتوثيق تفاصيل أخطاء إسناد الأدلة والتوقيت التي راجعها المحلل.  
- **Instructor caption (EN):** Continuation of the six validation flags, documenting reviewable evidence/timeline issues.

**05. `LT01-Human-Review-Corrected`** — `REVIEW CORRECTED`  
- **الشرح:** حفظ مراجعة المحلل البشري بالحالة Corrected بعد فحص أخطاء التفسير أو التوقيت؛ لا يعني اعتماد تقرير الذكاء الاصطناعي كما هو.  
- **Instructor caption (EN):** Human analyst correction of the LT-01 AI report after validation review.

**06. `LT01-Final-Verification-PASS`** — `PASS`  
- **الشرح:** التحقق النهائي من Hash المصدر والـFocused Dataset وربط 42/42 سطر بالمصدر، ثم تجهيز Timeline وCase Study وManifest.  
- **Instructor caption (EN):** Final source integrity, 42/42 provenance mapping, and final case documentation.

### LT-02 — Auditd privilege-sensitive command analysis

**01. `LT02-Source-Verification-PASS`** — `PASS`  
- **الشرح:** توثيق تنزيل مصدر Auditd الأصلي وقياس الحجم والـSHA-256؛ مصدر LT-02 به 108 سطر ضمن البيانات المختبرة.  
- **Instructor caption (EN):** Source acquisition and SHA-256 verification of the 108-line auditd original.

**02. `LT02-Auditd-Normalization-Parser-Verification`** — `VERIFICATION`  
- **الشرح:** مرحلة التحقق التفصيلي من فك ترميز أوامر Auditd وربط الـSerial والتوقيت وسطر المصدر بالمراجع؛ ليس إثباتًا لنجاح تنفيذ الأوامر.  
- **Instructor caption (EN):** Detailed normalized Auditd field, serial, timestamp, and source-line verification.

**03. `LT02-Auditd-Normalization-Parser-PASS`** — `PASS`  
- **الشرح:** نجاح الـNormalization لسجلات Linux Auditd بصيغة PROCTITLE واختبار Parser للعينة المركزة التي تضم 21 حدثًا.  
- **Instructor caption (EN):** Auditd PROCTITLE normalization and parser compatibility PASS for 21 focused events.

**04. `LT02-Human-Review-Corrected`** — `REVIEW CORRECTED`  
- **الشرح:** مراجعة بشرية مصححة لاستنتاجات غير مدعومة مثل شرعية الأوامر أو نجاح Privilege Escalation من وجود PROCTITLE فقط.  
- **Instructor caption (EN):** Corrected analyst review: PROCTITLE records do not by themselves establish authorization, execution success, or privilege escalation.

**05. `LT02-Final-Verification-PASS`** — `PASS`  
- **الشرح:** مطابقة SHA-256 للمصدر والملفات المشتقة وربط أحداث LT-02 الـ21 بسجلاتها الأصلية وإنشاء التقرير الزمني وCase Study.  
- **Instructor caption (EN):** Final auditd hash/mapping verification and evidence-based final documentation.

### LT-03 — Linux Sysmon Bash reverse-shell command

**01. `LT03-Source-Verification-PASS`** — `PASS`  
- **الشرح:** التحقق من ملف Splunk Linux Sysmon الأصلي (3466 بايت) بمطابقة Git LFS SHA-256 وحفظ Source Manifest.  
- **Instructor caption (EN):** Splunk Linux Sysmon source acquisition; 3,466-byte dataset checked against Git LFS SHA-256.

**02. `LT03-Linux-Sysmon-Inspection`** — `INSPECTION`  
- **الشرح:** فحص Linux-Sysmon Event ID 1: أمر Bash يحتوي /dev/tcp/10.0.255.12/4444 ولا توجد Event ID 3 في هذه العينة؛ التحقق من شكل XML.  
- **Instructor caption (EN):** Linux Sysmon Event ID 1 inspection showing a Bash /dev/tcp command, without separate connection telemetry in the sample.

**03. `LT03-Duplicate-Evidence-Verification`** — `DIAGNOSTIC`  
- **الشرح:** فحص مقارنة حدثين XML من Linux Sysmon لهما نفس EventRecordID وProcessGuid والتوقيت؛ مرحلة التشخيص قبل إزالة التكرار من العرض.  
- **Instructor caption (EN):** Investigation comparing two Linux Sysmon XML records for possible exact duplication.

**04. `LT03-Exact-Duplicate-Verification-PASS`** — `PASS`  
- **الشرح:** التحقق من التطابق الكامل لـRaw XML وEventRecordID وProcessGuid: سجلان أصليان لكن حدث فريد واحد؛ لا نحسب هجومين.  
- **Instructor caption (EN):** Exact XML duplicate verification: two source records, one unique observed process event.

**05. `LT03-Mistral-Reverse-Shell-Analysis`** — `AI OUTPUT`  
- **الشرح:** تشغيل Mistral لتحليل أمر Reverse Shell وتوثيق الاستنتاجات ومراجع الأدلة؛ بعض التشغيلات السابقة كشفت أخطاء Netcat وPrivate-IP وصححت لاحقًا.  
- **Instructor caption (EN):** Mistral reverse-shell investigation output, interpreted alongside human feedback and validator findings.

**06. `LT03-End-to-End-Grounding-Persistence-PASS`** — `PASS`  
- **الشرح:** إثبات حفظ قاعدة LINUX_BASH_REVERSE_SHELL_PATTERN داخل analysis.json لتحليل AN-20261019-021336-409d مع المرجع E001 وثقة High؛ دون إثبات نجاح الاتصال.  
- **Instructor caption (EN):** End-to-end persisted grounded reverse-shell detection (rule, E001, high pattern confidence), with network outcome unconfirmed.

### LT-04 — Low-risk Linux boot / service initialization

**01. `LT04-Source-Verification-PASS`** — `PASS`  
- **الشرح:** التحقق من Linux_2k.log من Loghub: 2000 سطر، 216485 بايت، Git Blob SHA-1 مطابق وSHA-256 محفوظ؛ ليس مصدرًا Benign معتمدًا بالكامل.  
- **Instructor caption (EN):** Pinned Loghub Linux_2k.log acquisition and integrity verification; mixed/unlabeled data, not a fully benign source.

**02. `LT04-Benign-Candidate-Inspection`** — `INSPECTION`  
- **الشرح:** فحص 2000 سطر Linux Syslog مختلطة؛ إظهار فشل المصادقة وأحداث FTP وlogrotate قبل استبعادها من تقييم Low-Risk.  
- **Instructor caption (EN):** Initial inventory of 2,000 mixed Linux syslog records before low-risk candidate screening.

**03. `LT04-Safe-Benign-Candidate-Selection`** — `SCREENING`  
- **الشرح:** تصفية سجلات SSH/FTP/الأخطاء وظهور 126 مرشحًا منخفض الخطورة؛ الاختيار النهائي يعتمد مراجعة السياق وليس الكلمة وحدها.  
- **Instructor caption (EN):** Conservative screening of Linux routine-operation candidates (126 candidates) before the final 18-event selection.

**04. `LT04-Focused-Candidate-Verification`** — `STOP / DIAGNOSTIC`  
- **الشرح:** توثيق محاولة التحضير الأولى التي توقفت عند مقارنة Raw Evidence للحدث E014 بسبب المسافات الطرفية؛ هذه Screenshot تشخيص فشل وليست PASS.  
- **Instructor caption (EN):** Initial preparation stopped on an E014 parser-versus-source trailing-whitespace difference; preserved as diagnostic evidence.

**05. `LT04-Focused-Candidate-Verification-PASS`** — `PASS`  
- **الشرح:** نجاح النسخة المصححة في إعداد 18 حدثًا، ربط 18/18 بالمصدر، وتوثيق فرق مسافات طرفية في حدثين دون تعديل المصدر الأصلي.  
- **Instructor caption (EN):** Corrected focused-set preparation: 18/18 mappings and documented whitespace-only parser differences.

**06. `LT04-Mistral-Benign-Analysis`** — `AI OUTPUT / REVIEW`  
- **الشرح:** تحليل Mistral الأول لسياق بدء تشغيل Linux؛ تعرف على النشاط العام لكنه أضاف تخمينًا غير مدعوم عن BIOS/Privilege Escalation.  
- **Instructor caption (EN):** Initial AI analysis of low-risk boot events; shows benign-context recognition plus unsupported BIOS/security speculation.

**07. `LT04-Post-Feedback-V2-Analysis`** — `COMPARATIVE EVALUATION`  
- **الشرح:** إعادة تحليل LT-04 بعد درس LT04_BOOT_BASELINE؛ تحسن Host=combo وتصنيف Syslog، لكن ظلت تخمينات BIOS وCPU Machine Check وجداول غير مكتملة.  
- **Instructor caption (EN):** Post-feedback-v2 Mistral comparison: better attribution but residual BIOS/machine-check speculation and timeline gaps.

### Cross-case evidence verification

**01. `LT03-LT04-Final-Documentation-PASS`** — `PASS`  
- **الشرح:** التحقق النهائي المشترك من LT-03 وLT-04: SHA-256 والـMapping وتوليد Timeline وCase Study وVerification Manifest لكل حالة دون تعديل الملفات القديمة.  
- **Instructor caption (EN):** Joint final verification and generation of six documentation outputs for LT-03 and LT-04.

### SOC Feedback, regression and semantic validation

**01. `SOC-Feedback-V2-147-Regression-PASS`** — `PASS`  
- **الشرح:** نجاح ترقية Feedback v2 مع زيادة اختبارات المشروع من 137 إلى 147 وإضافة قواعد مراجعة أخطاء BIOS وHost/Source.  
- **Instructor caption (EN):** Feedback v2 guarded upgrade: 137 to 147 passing regression tests and new LT-04 semantic checks.

**02. `SOC-Negation-Fix-177-Regression-PASS`** — `VERIFY IMAGE CONTENT`  
- **الشرح:** لقطة مسماة على أنها نجاح 177 اختبارًا لإصلاح فهم نفي Netcat؛ عدد 177 غير مُثبت من لقطات المخرجات المتاحة هنا ويلزم مراجعة محتوى الصورة نفسها قبل استخدام عبارة PASS في التقرير.  
- **Instructor caption (EN):** Purported 177-test Netcat-negation fix evidence. The pictured 177-test result has not been independently verified in the provided chat captures.

## 4. Evidence interpretation & limitations | حدود الإثبات

1. **LT-01:** تكرار `Failed password` يدعم نمط SSH brute force، لكنه لا يثبت نجاح تسجيل الدخول أو وصولًا غير مصرح به؛ لا تخلط بين الـ42 selected logs وبين الـ2,000 من المصدر الكامل.
2. **LT-02:** سجلات `type=PROCTITLE` توضح أوامر مسجلة (`setcap`, `chmod u+s`، وغيرها) ولا تثبت وحدها النجاح أو هوية المنفّذ أو تخويل العملية. عدة سجلات لا تعني بالضرورة عدة تنفيذات مستقلة.
3. **LT-03:** سجلا XML متطابقان ويجب عدم احتسابهما محاولتين؛ وجود `/dev/tcp` في الـCommandLine دليل على **نمط أمر Reverse Shell**، وليس إثبات اتصال TCP ناجح. `10.0.255.12` عنوان Private RFC1918.
4. **LT-04:** المصدر الكامل **مختلط وغير موسوم كـBenign**؛ الـ18 selected lines تمثل Low-Risk Boot/Service Initialization Candidates فقط. ليس هناك سنة أو Timezone صريحة في ترويسات Syslog. `machine check reporting enabled` لا يعني وقوع CPU Machine Check Error، و`BIOS-e820` لا يعني BIOS tampering.
5. **Automated validator:** عدد الـFlags هو عدد طلبات المراجعة، وليس عدد الهجمات أو عدد الأخطاء المؤكدة. `0 flags` لا يثبت صحة التقرير. كما أن الـReplay ينشئ تقييمًا جديدًا دون تغيير الـFlags الأصلية المحفوظة.
6. **Screenshot `177-Regression-PASS`:** يجب فتح الملف ومشاهدة سطر نتيجة اختبارات فعلي (`Ran 177 tests`, `OK`) قبل اعتماد العدد؛ الاسم وحده لا يكفي. اللقطات المعروضة في المحادثة تؤكد سابقًا 168 test passing، وReplay أخير بـ0 **new candidate flags** لكن ذلك ليس دليلًا مستقلًا على 177 tests.
7. **Parser diagnostic screenshots:** الصور التي تظهر `STOP` أو `File not found` هي سجل تشخيص وإصلاح، لا تُعرض ضمن قائمة PASS. احتفظ بها لإثبات منهجية الاختبار والتصحيح.

## 5. Additional screenshots recommended before instructor demo

هذه البنود **غير ظاهرة ضمن قائمة الصور الـ27 الحالية**؛ قد تكون موجودة خارج المجلد أو لم تُحفظ بعد. لا نُنشئ أسماء ملفات من غير صور مقابلة:

- `LT01-Source-Verification-PASS.png` — لقطة اختيارية منفصلة لتوثيق مصدر LT-01 لو كانت متاحة، وليست ضمن الصور الـ27 الظاهرة.
- `LT03-Human-Review-Corrected.png` — دليل الشاشة على حالة مراجعة LT-03 (الـCLI سجل Corrected).
- `LT04-Human-Review-Corrected.png` — دليل الشاشة على حالة مراجعة LT-04 (الـCLI سجل Corrected).
- `SOC-Grounded-Detection-168-Regression-PASS.png` — ظهور `Ran 168 tests ... OK` في التثبيت.
- `Grounded-Detection-Linux-4Cases-PASS.png` — تشغيل الأربع حالات في `demo.py --all` وعرض قواعد الاكتشاف.
- `Grounded-Detection-LT04-Semantic-Replay-PASS.png` — اكتشاف أخطاء BIOS/CPU بالـgrounding replay.
- `LT03-Netcat-Negation-Semantic-Replay-PASS.png` — إعادة فحص تحليل LT-03 بعد إصلاح Negation: `New candidate flags: 0` مع الاحتفاظ بـ5 original flags.

> لو عندك أي صورة من المذكور بالفعل باسم مختلف، سجل اسمها الحقيقي في فهرس جديد بدل نسخها أو تسميتها على إنها نتيجة غير موجودة.

## 6. How to build a protected copy + hash manifest

Put `README.md`, `organize_linux_screenshots.py`, and `screenshot_catalog.json` in the original `Evidence\Linux\Screenshots` folder. Run from that folder:

```powershell
Set-Location "D:\Desktop\w\Week-2\Evidence\Linux\Screenshots"
python .\organize_linux_screenshots.py --check
python .\organize_linux_screenshots.py --organize
```

The first command is **read-only**. The second copies recognized screenshots into sibling `Organized-Screenshots`, writes `Screenshot-Inventory.csv` and `Screenshot-Integrity-Manifest.json`, and **never overwrites** originals or any existing destination file. If names differ from those seen in Explorer, the report marks missing/unrecognized items for manual review. It does not alter `Core`, `Results`, `Data`, or `Evidence/Wazuh`.

## 7. Evidence chain for final report

The screenshot is supplemental evidence. To reproduce a result, connect the picture to: **original dataset + SHA-256 → focused dataset + selection manifest → Evidence Reference(s) → analysis ID / saved model output → automated validator → human review → final case study**. Preserve all originals, including failed/diagnostic runs, and present claims no stronger than the artifacts actually establish.

**Prepared for:** DEPI P5 — Week 2 Linux Evidence Documentation.  **Coverage:** 27 listed screenshots, plus a clearly marked recommended-evidence checklist.  **Wazuh:** retained as a separate planned/ongoing evidence domain.
