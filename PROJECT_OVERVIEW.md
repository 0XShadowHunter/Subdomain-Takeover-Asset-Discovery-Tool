# Subdomain Takeover & Asset Discovery Tool
## شرح المشروع (Project Overview)

---

## 1. فكرة المشروع

الأداة بتعمل حاجتين مترابطتين:

1. **Asset Discovery**: بتكتشف كل الـ Subdomains التابعة لدومين معين (مثلاً `example.com`) عشان نعرف حجم الـ Attack Surface الحقيقي للمؤسسة.
2. **Subdomain Takeover Detection**: بتفحص كل Subdomain اتلاقى وتشوف هل هو **"معلّق" (Dangling)**. يعني الـ DNS بتاعه لسه بيشاور على خدمة خارجية اتحذفت أو اتلغت، وده ممكن يسمح لمهاجم يسجّل نفس الخدمة ويسيطر على الـ Subdomain.

> **تنبيه أخلاقي وقانوني:** الأداة تُستخدم **فقط** على دومينات بتملكها أو معاك تصريح مكتوب بفحصها (Bug Bounty في الـ Scope / Pentest مصرّح). الأداة بتكتشف وتبلّغ، **مش** بتعمل Claim للخدمة ولا بتستغل الثغرة.

---

## 2. يعني إيه Subdomain Takeover؟

مثال:

```
blog.example.com  --CNAME-->  example.github.io
```

لو الشركة مسحت صفحة GitHub Pages بتاعتها لكن نسيت تمسح سجل الـ CNAME، يبقى `blog.example.com` بيشاور على حاجة مش موجودة. أي حد يقدر يعمل GitHub Pages بنفس الاسم، وساعتها يتحكم في محتوى `blog.example.com`.

**المخاطر:** سرقة Cookies، Phishing على دومين موثوق، تجاوز CSP/CORS، سمعة الشركة.

**الخدمات الشائعة المعرّضة:** GitHub Pages, AWS S3, Heroku, Azure, Netlify, Fastly, Shopify, Zendesk, Surge, Bitbucket، وغيرها.

---

## 3. الأداة بتعمل إيه (Pipeline)

```
Target Domain
     │
     ▼
[1] Subdomain Enumeration     ← تجميع الـ Subdomains من مصادر كتير
     │
     ▼
[2] DNS Resolution            ← حل الأسماء + استخراج CNAME chain + NXDOMAIN
     │
     ▼
[3] HTTP Probing              ← فحص الحالة، العنوان، الـ Body، الـ Headers
     │
     ▼
[4] Takeover Detection        ← مطابقة Fingerprints + منطق الـ NXDOMAIN
     │
     ▼
[5] Verification & Scoring    ← تقليل الـ False Positives وتصنيف الخطورة
     │
     ▼
[6] Reporting                 ← JSON / CSV / HTML / Markdown
```

---

## 4. الأدوات اللي بتعمل كل مرحلة

### 4.1 Subdomain Enumeration (Passive)
| الأداة | الوظيفة |
|---|---|
| **Subfinder** | تجميع من مصادر Passive كتير (APIs) |
| **Amass** | Enumeration + DNS mapping متقدم من OWASP |
| **Assetfinder** | سريعة وبسيطة من مصادر عامة |
| **Findomain** | سريعة، بتدعم مصادر Certificate Transparency |
| **crt.sh** | Certificate Transparency logs (API/DB) |
| **theHarvester** | OSINT: emails, hosts, subdomains |

### 4.2 Subdomain Enumeration (Active / Brute-force)
| الأداة | الوظيفة |
|---|---|
| **PureDNS** | Brute-force سريع مع فلترة Wildcards |
| **MassDNS** | Resolver عالي الأداء |
| **ShuffleDNS** | غلاف لـ MassDNS مع Wordlists |
| **dnsgen / altdns** | توليد Permutations للأسماء |

### 4.3 DNS Resolution & Analysis
| الأداة | الوظيفة |
|---|---|
| **dnsx** | حل DNS سريع واستخراج CNAME / A / NS |
| **dig / nslookup** | فحص يدوي للتأكد |
| **dnspython** | مكتبة Python للتكامل داخل الأداة |

### 4.4 HTTP Probing
| الأداة | الوظيفة |
|---|---|
| **httpx** (ProjectDiscovery) | Status code, title, tech detection, body hash |
| **requests / aiohttp** | بدائل داخل Python |

### 4.5 Takeover Detection
| الأداة | الوظيفة |
|---|---|
| **Subjack** | فحص CNAME مقابل Fingerprints |
| **Subzy** | فاحص Takeover سريع |
| **Nuclei** (Takeover templates) | Templates جاهزة للكشف |
| **dnsReaper** | فاحص شامل لأنواع Takeover |
| **can-i-take-over-xyz** | **المرجع** لقائمة الخدمات المعرّضة والـ Fingerprints |

### 4.6 Reporting
- **Jinja2** (HTML reports)، **pandas** (CSV)، **Rich** (Terminal output).

---

## 5. المنطق الأساسي للكشف (Detection Logic)

الـ Subdomain يُعتبر **مرشّح للـ Takeover** لما يتحقق واحد من:

1. **CNAME يشاور على خدمة معروفة + الـ HTTP Response بيطابق Fingerprint** الخدمة (مثلاً رسالة "There isn't a GitHub Pages site here").
2. **CNAME يشاور على دومين مش موجود (NXDOMAIN)**، وده الدومين ممكن يتسجّل.
3. **NS Delegation معلّق**: الـ NS records بتشاور على Nameservers مش شغالة أو متاحة للتسجيل.
4. **A Record على IP تابع لـ Cloud مش مستخدم** (Elastic IP محرّر)، وده أصعب في التأكد.

**مستويات الثقة (Confidence):**
- `HIGH`: CNAME لخدمة معرّضة + Fingerprint مطابق + الخدمة موثّقة في can-i-take-over-xyz
- `MEDIUM`: NXDOMAIN على CNAME target أو Fingerprint جزئي
- `LOW`: مؤشرات ضعيفة تحتاج مراجعة يدوية

---

## 6. التقنيات المقترحة (Tech Stack)

- **اللغة:** Python 3.10+
- **المكتبات:** `dnspython`, `aiohttp`/`httpx`, `asyncio`, `rich`, `jinja2`, `pyyaml`, `pytest`
- **أدوات خارجية (اختيارية):** subfinder, amass, dnsx, httpx, nuclei
- **التخزين:** JSON files أو SQLite
- **الواجهة:** CLI (أساسي) + HTML Report (اختياري Dashboard)

---

## 6.1 دعم أنظمة التشغيل (Windows + Linux / Kali)

الأداة لازم تشتغل بنفس السلوك على **Windows 10/11** و**Linux** (Kali, Ubuntu, Debian).

**المبدأ الأساسي:** الأداة بتشتغل **بـ Python بس** من غير أي أداة خارجية. الأدوات الخارجية (subfinder, amass, dnsx, httpx, nuclei) اختيارية وبتسرّع الشغل، ولو مش موجودة الأداة بتستخدم البديل المكتوب بـ Python.

| النقطة | الحل |
|---|---|
| المسارات | `pathlib` بس، من غير مسارات ثابتة |
| لقاء الأدوات الخارجية | `shutil.which()` (بيتعامل مع `.exe` على Windows) |
| اسم httpx على Kali | ممكن يكون `httpx-toolkit`، فالأداة بتدوّر على الاسمين |
| DNS | `dnspython` مع Resolvers مضمّنة (1.1.1.1 / 8.8.8.8 / 9.9.9.9) من غير اعتماد على `/etc/resolv.conf` |
| Async | `asyncio` عادي، من غير `uvloop` أو مكتبات Linux-only |
| الـ Terminal | مكتبة `rich` تشتغل على PowerShell و cmd و Kali |
| التثبيت | `scripts/setup.sh` لـ Linux/Kali و `scripts/setup.ps1` لـ Windows |
| الاختبار | CI على `windows-latest` و `ubuntu-latest` |

**أمثلة تشغيل (نفس الأمر على النظامين):**

```
# Linux / Kali
bash scripts/setup.sh
source .venv/bin/activate
python -m src.cli scan --domain example.com --report html

# Windows (PowerShell)
.\scripts\setup.ps1
.\.venv\Scripts\Activate.ps1
python -m src.cli scan --domain example.com --report html
```

---

## 7. هيكل المشروع المقترح

```
Subdomain-Takeover-Asset-Discovery-Tool/
├── README.md
├── PROJECT_OVERVIEW.md
├── AGENT_PLAN.md              ← خطة المراحل وتتبع التقدم
├── requirements.txt
├── pyproject.toml
├── .gitattributes
├── scripts/
│   ├── setup.sh               ← Linux / Kali
│   └── setup.ps1              ← Windows
├── .github/workflows/ci.yml   ← Windows + Ubuntu matrix
├── config/
│   ├── fingerprints.yaml      ← Fingerprints الخدمات
│   └── settings.yaml
├── src/
│   ├── cli.py
│   ├── discovery/             ← المرحلة 1
│   ├── resolver/              ← المرحلة 2
│   ├── detection/             ← المرحلة 3
│   ├── reporting/             ← المرحلة 4
│   ├── utils/
│   │   ├── platform.py        ← OS detection + find_tool()
│   │   └── paths.py           ← pathlib helpers
│   └── models.py              ← Data Contracts المشتركة
├── data/
│   ├── wordlists/
│   └── output/                ← مخرجات كل مرحلة (JSON)
├── tests/
└── docs/
```

---

## 8. تقسيم العمل على 4 أشخاص

| المرحلة | المسؤولية | المخرجات |
|---|---|---|
| **1** | Foundation + Subdomain Enumeration | `data/output/phase1_subdomains.json` |
| **2** | DNS Resolution + HTTP Probing | `data/output/phase2_resolved.json` |
| **3** | Takeover Detection + Verification | `data/output/phase3_findings.json` |
| **4** | Reporting + CLI + Testing + Docs | تقارير نهائية + عرض التخرج |

كل مرحلة بتاخد مدخلاتها من JSON مرحلة اللي قبلها، فكل شخص يقدر يشتغل باستقلالية. التفاصيل الكاملة في `AGENT_PLAN.md`.

---

## 9. مراجع مفيدة

- can-i-take-over-xyz (GitHub): قائمة الخدمات المعرّضة
- OWASP: Testing for Subdomain Takeover (WSTG-CONF-10)
- ProjectDiscovery: subfinder, dnsx, httpx, nuclei
- HackerOne / Bugcrowd: تقارير Subdomain Takeover منشورة
