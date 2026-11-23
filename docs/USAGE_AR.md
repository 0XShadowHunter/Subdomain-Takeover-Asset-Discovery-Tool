# كتالوج الاستخدام الكامل — subtake 📖

> دليل الاستخدام بالعربي لكل أوامر الأداة. المرجع التقني بالإنجليزية في `README.md`.
>
> ⚠️ **تذكير:** استخدم الأداة فقط على دومينات تملكها أو معاك تصريح مكتوب
> (bug bounty داخل الـ scope / اختبار اختراق مصرّح به / أهداف تجريبية).
> الأداة بتكتشف وتبلّغ بس — مش بتعمل claim ولا بتستغل أي ثغرة.

---

## 0) التشغيل لأول مرة

```powershell
cd G:\Subdomain-Takeover-Asset-Discovery-Tool
.\.venv\Scripts\Activate.ps1          # تفعيل البيئة الافتراضية
python -m src.cli --help              # اعرض كل الأوامر
```

> لو `Activate.ps1` اتمانع: `powershell -ExecutionPolicy Bypass` أو
> `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`

على Linux/Kali: `source .venv/bin/activate`

---

## 0.1) التسطيب كبرنامج (زرار Setup واحد) 🧰

بدل ما تفعّل الـ venv كل مرة — دبل كليك على:

```
scripts\install.bat
```

اللي هيحصل: تسطيب البرنامج (أوامر `subtake` و `subtake-gui` تشتغل من أي تيرمنال بعد تفعيل الـ venv) + **اختصار "subtake GUI" على الديسكتوب**.

### النسخة المستقلة تمامًا (بدون Python خلاص)

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install.ps1 -BuildExe -Shortcut
```

هتبني `dist\subtake.exe` (~19MB) — برنامج قائم بذاته بأيقونة اللوجو الرسمية، **Windowed build: الدبل كليك يفتح البرنامج من غير أي نافذة cmd سودا** 🖤، والـ fingerprints والقوالب وقائمة الكلمات واللوجو كلهم جواه. ومن التيرمنال يشتغل CLI عادي (بيتمسك بكونسول الأب تلقائيًا).

---

## 0.2) الواجهة الرسومية GUI 🖱️

للمستخدمين اللي مش حابين التيرمنال:

```powershell
python -m src.cli gui        # أو: subtake-gui   |   أو دبل كليك على dist\subtake.exe
```

**شاشة ترحيب (Splash):** عند فتح الأداة، اللوجو **وحده** يظهر في نافذة داكنة وسط الشاشة ~2 ثانية ثم تفتح الأداة. (الوصف التفصيلي التالي من نسخة أقدم): عند الفتح، اللوجو الكبير بيظهر في نافذة ترحيب داكنة وسط الشاشة مع شريط تحميل متحرك لمدة ~2 ثانية، وبعدها الأداة تفتح مباشرة (الـ CLI مش متأثر — بيفضل ببانر الـ ASCII).

| العنصر | وظيفته |
|---|---|
| **Target domain** | الدومين الهدف (مثال `example.com`) |
| Threads / Timeout | نفس معاني الـ CLI |
| Resolvers | الـ DNS resolvers مفصولة بمسافة |
| Skip brute-force | passive فقط |
| Wordlist (Browse…) | قائمة كلمات مخصصة |
| Output folder (Browse…) | مكان النتايج والتقارير |
| Report formats ✅ | html / csv / markdown / json |
| **▶ Start scan** | يشتغل المراحل الثلاثة + التقارير |
| Live log | سجل حي داخل النافذة |
| Findings table | النتايج مرتبة بالخطورة وملونة |
| 📂 Open output folder | يفتح مجلد التقارير مباشرة |

نفس محرك الفحص بتاع الـ CLI بالظبط — مفيش كود مكرر.

---

## 1) الأمر الشامل: `scan` ⭐ (الأهم — أمر واحد يشتغل كل حاجة)

**بيعمل:** اكتشاف الـ subdomains ← فحص DNS + HTTP ← كشف الـ Takeover ← توليد التقارير.

```powershell
python -m src.cli scan --domain example.com --format all
```

| الخيار | القيمة الافتراضية | الشرح |
|---|---|---|
| `--domain` | **مطلوب** | الدومين الهدف، مثال: `example.com` |
| `--threads N` | `100` | عدد العمليات المتوازية (آمن على Windows وLinux) |
| `--timeout N` | من `settings.yaml` (10) | مهلة الشبكة بالثواني |
| `--resolvers IP IP ...` | `1.1.1.1 8.8.8.8 9.9.9.9` | تغيير الـ DNS resolvers |
| `--skip-brute` | — | تخطي الـ brute-force (passive فقط) |
| `--wordlist PATH` | `data/wordlists/subdomains.txt` | قائمة كلمات مخصصة |
| `--output-dir PATH` | `data/output` | مجلد كل المخرجات والتقارير |
| `--format F` | `html` | `all` أو قائمة مفصولة بفواصل: `json,csv,markdown,html` |

**أمثلة:**

```powershell
# تقرير HTML بس (سريع)
python -m src.cli scan --domain example.com

# كل التقارير + brute-force أسرع بكلمة مخصصة + مجلد مخصص
python -m src.cli scan --domain example.com --format all --threads 50 --wordlist big.txt --output-dir results

# passive فقط بدون أي استعلامات brute-force
python -m src.cli scan --domain example.com --skip-brute
```

**المخرجات — فولدر أساسي واحد، والـ CLI منفصل عن الـ GUI 🗂️:**

كل نتايج الحفظ (SQLite + الملفات) بتتخزن في الفولدر الأساسي **`data\results\`** — بداخله مساحة لكل مصدر:

```
data\results\
├── cli\                          ← الفحوصات اللي بدأت من سطر الأوامر
│   └── amit-learning.com\
│       ├── phase1_subdomains.json
│       ├── phase2_resolved.json
│       ├── phase3_findings.json
│       ├── subtake.db            ← SQLite: تاريخ كل فحوصات الدومين ده من الـ CLI
│       └── report.html / .csv / .md / .json
└── gui\                          ← الفحوصات اللي بدأت من الواجهة الرسومية
    └── amit-learning.com\
        └── subtake.db ...
```

| الملف | المحتوى |
|---|---|
| `phase1_subdomains.json` | الـ subdomains المكتشفة + مصدر كل واحد |
| `phase2_resolved.json` | سجلات DNS (A/AAAA/CNAME/NS) + بيانات HTTP |
| `phase3_findings.json` | الثغرات: evidence + confidence + severity + remediation |
| `subtake.db` | **SQLite** — كل فحص الدومين ده (الأسامي + الـ IPs + الـ CNAME + الثغرات) — يتراكم مع كل تشغيل جديد |
| `report.html` | تقرير تفاعلي يفتح في المتصفح (الأفضل للعرض) |
| `report.csv` | جدول يفتح في Excel |
| `report.xlsx` | **شيت Excel حقيقي**: Summary + Subdomains + Findings ملونة بالخطورة |
| `report.md` | تقرير نصي للـ Git/GitHub |
| `report.json` | نسخة JSON للتقارير البرمجية |

استعلام من قاعدة الدومين:

```bash
sqlite3 data/results/cli/example.com/subtake.db "SELECT subdomain, severity, remediation FROM findings WHERE confidence='HIGH'"
```

> **في الـ GUI:** أول ما تكتب الدومين، خانة **Output folder** بتتحدث لوحدها لـ `data\results\gui\<domain>\` — ولو كتبت مجلد بنفسك، اختيارك محترم ومش بيتكتب فوقه.
>
> **الـ exe المستقل:** بنفس الهيكل لكن جنب مكان الـ exe (`<exe folder>\data\results\...`).

| الملف | المحتوى |
|---|---|
| `phase1_subdomains.json` | الـ subdomains المكتشفة + مصدر كل واحد |
| `phase2_resolved.json` | سجلات DNS (A/AAAA/CNAME/NS) + بيانات HTTP |
| `phase3_findings.json` | الثغرات: evidence + confidence + severity + remediation |
| `subtake.db` | **SQLite** — كل فحص الدومين ده (الأسامي + الـ IPs + الـ CNAME + الثغرات) — يتراكم مع كل تشغيل جديد |
| `report.html` | تقرير تفاعلي يفتح في المتصفح (الأفضل للعرض) |
| `report.csv` | جدول يفتح في Excel |
| `report.xlsx` | **شيت Excel حقيقي**: Summary + Subdomains + Findings ملونة بالخطورة |
| `report.md` | تقرير نصي للـ Git/GitHub |
| `report.json` | نسخة JSON للتقارير البرمجية |

استعلام من قاعدة الدومين:

```bash
sqlite3 data/output/example.com/subtake.db "SELECT subdomain, severity, remediation FROM findings WHERE confidence='HIGH'"
```

> الـ GUI بتعمل نفس الحاجة: أول ما تكتب الدومين، خانة **Output folder** بتتحدث لوحدها لـ `data\output\<domain>\` — ولو كتبت مجلد بنفسك، اختيارك محترم ومش بيتكتب فوقه.

---

## 2.5) أمر `clean` — مسح سجلات الدومين المحفوظة 🗑️

بيمسح كل السجلات المحفوظة لدومين من قاعدة SQLite (واختياريًا مجلد النتايج كله):

```powershell
# مسح سجل الفحص من قاعدة البيانات (مع تأكيد)
python -m src.cli clean --domain amit-learning.com

# مسح السجل + مجلد النتايج بالكامل
python -m src.cli clean --domain amit-learning.com --purge-files

# بدون أسئلة (للـ CI والسكربتات)
python -m src.cli clean --domain amit-learning.com --purge-files --yes

# قاعدة بيانات بمسار مخصص
python -m src.cli clean --domain amit-learning.com --db path\to\subtake.db
```

| الخيار | الشرح |
|---|---|
| `--domain` | **مطلوب** — الدومين اللي هتنضف سجلاته |
| `--purge-files` | يمسح كمان مجلد النتايج كامل `data\output\<domain>\` |
| `--db PATH` | مسار قاعدة بديل (الافتراضي: مجلد الدومين) |
| `--yes` | تخطي رسائل التأكيد |

**الأمان:** الأمر بيعرض بالظبط هيمسح كام سجل قبل التنفيذ، بيرفض يشتغل في الجلسات غير التفاعلية بدون `--yes`، وحذف المجلد بيتحصر في مجلد الدومين الافتراضي بس. وفي الـ GUI فيه زرار **🗑 Clear saved results** بنفس الحماية (رسائل تأكيد قبل أي حذف).

---

## 2) تشغيل المراحل منفصلة (مفيد للفحص المتدرج)

### `discover` — المرحلة 1: اكتشاف الـ subdomains

```powershell
python -m src.cli discover --domain example.com
```

| الخيار | الافتراضي | الشرح |
|---|---|---|
| `--domain` | **مطلوب** | الدومين الهدف |
| `--wordlist PATH` | `data/wordlists/subdomains.txt` | قائمة كلمات للـ brute-force |
| `--skip-brute` | — | بدون brute-force |
| `--threads N` | `100` | التوازي |
| `--resolvers ...` | 1.1.1.1/8.8.8.8/9.9.9.9 | resolvers مخصصة |
| `--output PATH` | `data/output/phase1_subdomains.json` | ملف المخرج |

مصادر الاكتشاف: **crt.sh** (دائمًا) + **subfinder/amass/assetfinder** (لو متسطبة — اختيارية) + **brute-force** مع فلترة الـ wildcard.

### `resolve` — المرحلة 2: فحص DNS + HTTP

```powershell
python -m src.cli resolve
```

| الخيار | الافتراضي | الشرح |
|---|---|---|
| `--input PATH` | `data/output/phase1_subdomains.json` | ملف مخرج المرحلة 1 |
| `--threads N` | `100` | التوازي |
| `--resolvers ...` | 1.1.1.1/8.8.8.8/9.9.9.9 | resolvers مخصصة |
| `--rate N` | بدون تحديد | أقصى عدد طلبات HTTP في الثانية |
| `--output PATH` | `data/output/phase2_resolved.json` | ملف المخرج |

بيعمل لكل subdomain: A/AAAA + سلسلة CNAME كاملة (بحماية من اللوب) + NS + فحص HTTP (https ثم http) بيجمع: الحالة، العنوان، الـ headers، أول 2KB، سلسلة الـ redirects، وأخطاء TLS.

### `detect` — المرحلة 3: كشف الـ Takeover

```powershell
python -m src.cli detect
```

| الخيار | الافتراضي | الشرح |
|---|---|---|
| `--input PATH` | `data/output/phase2_resolved.json` | ملف مخرج المرحلة 2 |
| `--fingerprints PATH` | `config/fingerprints.yaml` | قاعدة بصمات الخدمات (قابلة للتعديل) |
| `--no-recheck` | — | إيقاف إعادة التأكد بـ DNS تاني (أسرع، أقل دقة) |
| `--output PATH` | `data/output/phase3_findings.json` | ملف المخرج |

**الكواشف الأربعة:**

| الكاشف | النوع | متى يطلق | الثقة |
|---|---|---|---|
| 1 | `CNAME_FINGERPRINT` | CNAME لخدمة معروفة + البصمة ظاهرة في صفحة الـ 404 | HIGH (vulnerable) / MEDIUM (edge) |
| 2 | `CNAME_NXDOMAIN` | الـ CNAME يشاور على اسم مش موجود (مؤكد بخط DNS تاني) | MEDIUM (HIGH لو الهدف قابل للتسجيل) |
| 3 | `NS_DELEGATION` | الـ zone متفوضة كليًا لـ nameservers ميتة | MEDIUM |
| 4 | `DANGLING_A` | سجل A صفحته مطابقة لبصمة مخصصة (اختياري — مقفول افتراضيًا) | LOW |

---

## 3) خيارات عامة (قبل اسم الأمر)

```powershell
python -m src.cli -v discover --domain example.com     # -v = تفاصيل Debug
python -m src.cli --settings my-settings.yaml scan --domain example.com
```

| الخيار | الشرح |
|---|---|
| `-v` / `--verbose` | تسجيل تفصيلي (Debug) |
| `--settings PATH` | ملف إعدادات بديل (الافتراضي `config/settings.yaml`) |

---

## 4) الإعدادات والتخصيص

### `config/settings.yaml`
- `general.timeout` — مهلة الشبكة (ثواني)
- `general.concurrency` — التوازي
- `general.resolvers` — الـ DNS resolvers (مش إعدادات النظام)
- `sources.*` — تشغيل/إيقاف كل مصدر + مهلة كل واحد

### `config/fingerprints.yaml` (بدون أي تعديل في الكود)
- أضف خدمة جديدة: انسخ شكل الـ entry وعدّل `cname_patterns` + `fingerprints`
- `status`: `vulnerable` (ثقة HIGH) / `edge-case` (MEDIUM) / `not-vulnerable` (لا يُرفع أبدًا)
- `detection.recheck_dns` — الفحص مرتين (افتراضي مفعّل)
- `detection.enable_dangling_a` — تشغيل الكاشف الرابع (افتراضي متقفول)

---

## 5) قراءة النتائج

| الحقل | المعنى |
|---|---|
| `severity` | الخطورة: `CRITICAL` (يدوي) > `HIGH` > `MEDIUM` > `LOW` > `INFO` |
| `confidence` | ثقة الأداة: HIGH = خدمة مصابة + بصمة مطابقة / MEDIUM = مؤشر قوي محتاج تأكيد يدوي / LOW = فحص أولي |
| `evidence` | الدليل الحرفي (البصمة المطابقة / تأكيد الـ DNS التاني) |
| `remediation` | نصيحة الإصلاح (استشارية) |
| `summary.vulnerable` | عدد الـ findings بثقة HIGH |

**قاعدة ذهبية:** كل finding أعد التحقق منه يدويًا قبل أي إجراء — الأداة بتعطيك مؤشرات مدروسة مش أحكام نهائية.

---

## 6) حالات الخروج (Exit Codes)

| الكود | المعنى |
|---|---|
| `0` | نجح |
| `2` | مدخل غير صالح (دومين غلط / ملف مفقود / format غلط) |
| `3` | أمر غير متاح |
| `130` | مقاطعة يدوية (Ctrl+C) |
| `1` | فشل مرحلة داخل `scan` |

---

## 7) مشاكل شائعة سريعة

| المشكلة | الحل |
|---|---|
| `crt.sh returned HTTP 502` | طبيعي — الموقع مزدحم؛ التشغيل بيكمل من غيره. جرّب لاحقًا. |
| `xxx is not installed — skipping` | أدوات اختيارية مش متسطبة — معلوماتية بس. |
| PowerShell مانع `Activate.ps1` | `powershell -ExecutionPolicy Bypass` |
| نتايج DNS مختلفة بين جهازين | الأداة بتستخدم resolvers ثابتة (مش النظام) — اتأكد من `--resolvers` |
| عايز فحص أسرع | `--threads 50` أو `--skip-brute` |
| عايز فحص أهدى (rate limit) | `resolve --rate 20` |

---

## 8) أوامر الجودة (للتطوير)

```powershell
python -m pytest -q          # 130 اختبار
ruff check src tests         # فحص الكود
```
