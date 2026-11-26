# Week 4 بالعربي — دليل لأي حد بيفتح الأسبوع ده لأول مرة

## ١. الأسبوع ده كان مطلوب فيه إيه؟
الـbrief بتاع DEPI بيقول:

> شغّلوا **محاكاة كاملة لحادثة** فيها مراحل network وendpoint وweb، وامشوا فيها على **دورة الاستجابة للحوادث (NIST/SANS)**: detection ثم triage ثم containment ثم eradication ثم recovery ثم post-incident. **استخدموا الـAI في كتابة الـdrafts، والإنسان يراجع ويعتمد.**

والمطلوب تسليمه 7 حاجات:
1. Final Capstone IR Report
2. Incident timeline
3. Forensic evidence summary
4. Containment / recovery plan
5. Executive briefing
6. Lessons-learned
7. AI-assisted reporting workflow

وإحنا زوّدنا عليهم **SOC dashboard**.

## ٢. عملنا إيه في جملتين
جمعنا كل اللي اتعمل في Weeks 1 و2 و3 في **حادثة واحدة** اسمها `W4-TT-01`، ومشينا فيها على مراحل NIST كلها. **كل رقم وكل توقيت في الشغل متاخد من ملفات موجودة فعلًا في الريبو**، والكود هو اللي بيقراها، ومفيش حاجة متكتبة بالإيد.

## ٣. ليه "Composite Tabletop"؟
الداتا اللي عندنا جاية من datasets مختلفة، من مصادر مختلفة وسنين مختلفة من 2019 لـ2026. يعني مفيش هجمة واحدة حقيقية ماشية من الأول للآخر. فبدل ما نألف هجمة، رتبنا **الحالات الحقيقية** على مراحل الـkill chain، وعملنا عليها تمرين استجابة (tabletop):

| المرحلة | إيه اللي حصل | الحالات |
|---|---|---|
| S1 | Port scan | NT-01 |
| S2 | هجوم على الويب (طلبات HTTP كتير + XSS) | SIEM-WEB-001, SIEM-WEB-004 |
| S3 | تخمين باسوورد SSH | SIEM-AUTH-002, LT-01 |
| S4 | تشغيل ملف مشبوه + reverse shell | SIEM-MAL-003, LT-03 |
| S5 | Persistence (Winlogon) + أوامر sudo | RT-04, LT-02 |
| S6 | مسح الـSecurity log | RT-02 |
| S7 | Lateral movement بـWinRM على الـDC | RT-03 |
| S8 | C2 (اتصالات متكررة + DNS burst + plink tunnel) | NT-03, NT-02, RT-01 |
| S9 | Export للإيميلات على Exchange (فرضية exfiltration) | SIEM-EXCH-005 |
| FP | حالات عادية عشان نبيّن إن الـtriage بيفرّق | BT-01..03, LT-04 |

**مهم:** الربط بين المراحل ده سيناريو للتمرين، مش إننا شفنا مهاجم بينقل من مرحلة للتانية. والتوقيتات اللي ظاهرة هي التوقيتات الأصلية للداتا، ومفيش أي توقيت اتغيّر. ده مكتوب في كل تقرير وفي الداشبورد.

## ٤. الشغل ماشي إزاي (بالترتيب)
| الخطوة | الملف | بيعمل إيه |
|---|---|---|
| 1 | `IR/correlate.py` | بيقرا ملفات Weeks 1–3 ويطلع incident واحد: الحالات، والـtimeline، والـIOCs، والـIPs المشتركة بين datasets مختلفة، والـATT&CK |
| 2 | `IR/ir_lifecycle.py` | بيحسب حالة كل مرحلة من مراحل NIST، وبيطلع الاقتراحات (containment / eradication / recovery) من tickets بتاعة Week 3 ومن `Config/response_catalog.json` |
| 3 | `IR/t0_checks.py` | بيعمل الفحوصات اللي بتقرا بس (read-only) على داتا الريبو |
| 4 | `IR/suggest.py` | بيقترح قرار لكل بند بقواعد ثابتة مكتوبة في أول الملف |
| 5 | `IR/ai_report_drafter.py` | بيبعت الحقايق لـMistral على الجهاز نفسه، وبعدين الـvalidator بتاع Week 2 يراجع اللي اتكتب |
| 6 | `IR/build_reports.py` | بيطلع الـ7 تقارير |
| 7 | `IR/build_dashboard.py` | بيطلع الداتا اللي الداشبورد بتقراها |
| — | `IR/ir_cli.py` | الأمر الوحيد اللي بتشغّل بيه كل ده |

ملفات Weeks 1 و2 و3 **بتتقري بس ومش بتتعدل**، وفيه test بيتأكد من كده.

## ٥. مراحل NIST اتعملت إزاي
- **Preparation:** بيتأكد إن معمل الـAI والـprompts والـprivacy checklist بتوع Week 1، والـplaybooks بتوع Week 3، موجودين كلهم.
- **Detection:** فيه 5 alerts من OpenObserve، و10 حالات هجوم من الـdatasets، و4 حالات عادية.
- **Triage:** الـAI عمل triage للـ19 حالة. والـ14 dataset case عليهم مراجعة بشرية من Week 2.
- **Containment / Eradication / Recovery:** كل بند فيهم عليه قرار مسجل. والمرحلة مابتبقاش complete غير لما كل بنودها ياخدوا قرار.
- **Post-incident:** Mistral كتب 12 draft، وكلهم اتراجعوا.

### أنواع البنود (نفس اللي في Week 3)
| النوع | معناه | القرارات المسموحة |
|---|---|---|
| **T0** | فحص بيقرا بس، ومش بيغيّر أي حاجة | `done` أو `deferred` |
| **T1** | اقتراح محتاج موافقة الـanalyst، والتنفيذ بيعمله إنسان برّه السيستم | `approved` أو `rejected` أو `deferred` |
| **T2** | ممنوع ينفذ أوتوماتيك خالص | الأمر بيرفض يسجّل عليه قرار |

**القرارات اللي اتسجلت:** 45 قرار (19 approved و18 deferred و8 done). كلهم اقتراحات القواعد، والـanalyst وافق عليها باسمه، وده متسجل في `Simulation/analyst_decisions.jsonl`. **ومفيش أي حاجة اتنفذت فعلًا.**

## ٦. الـAI كتب إيه، ومين راجعه؟
1. الكود بيجهّز **ورقة حقايق مترقمة** (`[E001]`، `[E002]`…) من الداتا.
2. بيبعتها لـ**Mistral 7B على اللابتوب نفسه**، من غير إنترنت ولا cloud.
3. الـvalidator بتاع Week 2 بيدوّر على IP أو hash أو توقيت مش موجود في الحقايق.
4. الـanalyst بيقرا الـdraft ويسجّل عليه **Approved**، أو **Corrected** ويكتب النسخة المصلحة في `*.corrected.md`. النسخة الأصلية اللي كتبها الـAI بتفضل محفوظة.

**النتيجة:** 12 draft، منهم 5 Approved و7 Corrected.

**أهم حاجة اتعلمناها:** الـvalidator بيمسك المعلومات المتألفة، زي IP مش موجود، لكن **مش بيمسك المعنى الغلط**. 7 drafts طلعوا بصفر أو علامة واحدة بس، ومع ذلك كان فيهم غلطات في المعنى. مثلًا كتب "unauthorized" كأنها حقيقة، وقال إن الصلاحية اتدّت بعد الـexport وهي اتدّت قبله. **عشان كده المراجعة البشرية مش اختيارية.**

## ٧. أهم حاجات لقيناها في الداتا
- **Exchange:** السجل الكامل بيبيّن إن نفس التسلسل اتكرر مرتين: Administrator خد صلاحية Mailbox Import Export، وبعدين اتعمل export لملف `.aspx`، وبعد حوالي ٥ دقايق **اتمسح طلب الـexport واتمسح الإيميل نفسه**. السجلات دي كانت في داتا Week 2 ومحدش كان استخدمها.
- **SSH:** مفيش ولا login ناجح من الـIP بتاع الـbrute force في الـ2000 سطر.
- **Port scan:** 11 port بس من 65535 ردّوا: `22, 135, 139, 445, 5040, 49664–49669`.
- **IPs مشتركة بين datasets مختلفة:**
  - `183.62.140.253` في LT-01 وSIEM-AUTH-002.
  - `192.168.16.132` هو الـscanner في NT-01، وهو كمان اللي عمل الـDNS burst في NT-02.

## ٨. الداشبورد بتعمل إيه؟
`Dashboard/index.html` صفحة واحدة بتفتحيها بدبل كليك، وشغالة من غير إنترنت. بتعرض المشروع كله في شاشة واحدة، وأي رقم لو وقفتي عليه بالماوس هيقولك جاي من أنهي ملف.

| الصفحة | بتوريكي إيه |
|---|---|
| **Overview** | الأرقام الأساسية، والـ9 مراحل، وحالة مراحل NIST، وحالة المراجعة البشرية، وتقييم الـAI للـalerts |
| **Attack chain** | الهجمة مرسومة كجدول: الصفوف مجالات (network / web / auth / endpoint / email) والأعمدة مراحل. وتحتها الـIPs المشتركة وجدول MITRE ATT&CK |
| **Alerts & cases** | الـ19 حالة. اضغطي على أي واحدة تفتح تفاصيلها: الـevidence، والـAI، والمراجعة، والـtickets، والـhashes |
| **Timeline** | الأحداث بترتيب المراحل، بالتوقيت الأصلي ونوعه (مثلًا "من غير سنة ولا timezone") |
| **Response (NIST)** | كل بند ونوعه ونتيجة الفحص والاقتراح والقرار واسم اللي قرره. وزرار Copy بيجيبلك أمر القرار جاهز |
| **SOAR (Week 3)** | الـ4 playbooks، والـ7 tickets، وجدول قرارات الأتمتة |
| **AI quality (W1–W4)** | مقارنة الموديلات في Week 1، ونتايج الـvalidator والمراجعة في Week 2، والـ12 draft بتوع Week 4 ونص كل واحد (View) |
| **Evidence & IOCs** | الـIPs والـdomains والـhashes، مقسمين لـindicator وcontext، ومعاهم الـSHA-256 لكل ملف evidence |
| **Reports & run** | لينكات الـ7 تقارير، والحاجات اللي لسه مفتوحة من Week 2 و3، وأوامر التشغيل |

**الألوان:**
- **ألوان المجالات** بس عشان تفرّقي بينها، وكل لون مكتوب جنبه اسمه.
- **النقط:** الأخضر = تمام، البرتقالي = مستني، الأحمر = مرفوض.
- **High وMedium** دول تقييم الـAI، مش قرار analyst.

الشرح الكامل بالإنجليزي في `Documentation/Dashboard-Guide.md`.

## ٩. فين كل حاجة
| عايزة إيه | افتحي |
|---|---|
| ملخص الأسبوع كله | `Week-4-Final-Report.md` |
| الـ7 تقارير المطلوبة | `Reports/01..07` |
| الداشبورد | `Dashboard/index.html` |
| الحقايق اللي الكود طلعها | `Output/incident.json`، `incident_timeline.csv`، `observables.csv` |
| الفحوصات | `Output/t0_checks.json` |
| اللي Mistral كتبه + التصحيحات | `Output/ai_drafts/` |
| القرارات والمراجعات | `Simulation/` |
| السيناريو والـATT&CK والاقتراحات | `Config/` |

## ١٠. تشغيله من الأول على جهاز جديد
محتاجة Python 3.9 أو أحدث، وOllama وعليه `mistral:7b-instruct-v0.3-q4_K_S`. والأوامر بتتشغل من فولدر الريبو:
```cmd
python -B Week-4/IR/ir_cli.py build
python -B Week-4/IR/tests/run_all.py
python -B Week-4/IR/ir_cli.py draft
python -B Week-4/IR/ir_cli.py status
```
- `build` بيعمل كل حاجة من غير AI: التقارير والداشبورد.
- التستات لازم تطلع `SUMMARY: 18/18 passed`.
- `draft` بيشغّل Mistral عشان يكتب الـ12 draft. على لابتوب من غير GPU بياخد حوالي ساعة.
- `status` بيوريكي إيه اللي لسه مستني قرار.

وأوامر القرارات والمراجعة:
```cmd
python -B Week-4/IR/ir_cli.py accept-suggestions --analyst "الاسم"
python -B Week-4/IR/ir_cli.py review --draft stage_S1 --status Approved --analyst "الاسم"
```

## ١١. اللي المشروع **مش** بيدّعيه
- مش حادثة حقيقية ولا مراقبة production. ده تمرين على داتا lab قديمة.
- الربط بين المراحل سيناريو، مش علاقة سبب ونتيجة اتشافت في الداتا.
- الـATT&CK اللي عليه "candidate" أو "hypothesis" مش مؤكد.
- مفيش أي action اتنفذ. "approved" معناها "الـanalyst كان هيعمل كده".
- مفيش threat intelligence حقيقي، فسمعة أي IP "not checked".

## ١٢. أسئلة متوقعة في المناقشة
- **ليه مش هجمة live؟** الـbrief طالب simulation، وإحنا عملناها tabletop على evidence حقيقي ومتحقق منه بدل ما نألف داتا.
- **إزاي نضمن إن مفيش أرقام متألفة؟** فيه tests بتتأكد إن كل timestamp وكل IP موجود بالحرف في الملف اللي جاي منه، وإن الـSHA-256 بتاع كل ملف evidence متطابق.
- **الـAI بيقرر؟** لأ. الـAI بيكتب drafts بس، والـvalidator بيعلّم على المعلومات المتألفة، والـanalyst هو اللي بيعتمد أو بيصحح. والقرارات مسجلة باسم الـanalyst.
- **الاقتراحات مين عملها؟** قواعد ثابتة ومكتوبة في `IR/suggest.py`، والـanalyst وافق عليها، وده متسجل جنب كل قرار (`accepted_rule_suggestion`).
- **ليه Mistral كان بطيء؟** اللابتوب اللي اتعمل عليه التشغيل ماكانش بيستخدم الـGPU، فالسرعة كانت حوالي 2 token في الثانية. في Week 1 على GPU كانت 23.1.
