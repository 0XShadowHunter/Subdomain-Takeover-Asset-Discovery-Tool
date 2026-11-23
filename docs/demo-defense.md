# سيناريو العرض التجريبي وخطة المناقشة (Graduation Defense)

## أولاً: سيناريو العرض العملي (Demo) — آمن بالكامل

كل الخطوات على دومين `example.com` (محجوز IANA للتجارب) وعلى ملفات الـ demo
المرفقة — بدون أي هدف حقيقي بدون تصريح.

### الخطوة 1 — الاكتشاف (≈ 1 دقيقة)

```powershell
.\.venv\Scripts\Activate.ps1
python -m src.cli discover --domain example.com
```

النقاط اللي تتكلم عنها أثناء التشغيل:
- تحذير التخويل بيظهر أول حاجة (الالتزام الأخلاقي).
- الأدوات الخارجية اختيارية — لو مش موجودة بيكمل بدونها.
- الـ wildcard detection بيمنع تشويش النتايج.

### الخطوة 2 — الفحص (DNS + HTTP)

```powershell
python -m src.cli resolve
```

اعرض من `data\output\phase2_resolved.json`: سجلات A/AAAA، سلسلة CNAME،
الحالة 200، الـ title والـ headers.

### الخطوة 3 — الكشف

```powershell
python -m src.cli detect
```

النتيجة المتوقعة على example.com: صفر findings — قول هنا:
"الأداة صارمة في تقليل الإنذارات الكاذبة — مضيف سليم = صفر نتائج".

### الخطوة 4 — إثبات الكشف (الـ Demo المصنّع)

```powershell
python -m src.cli detect --input data\output\phase2_demo_dangling.json --output data\output\phase3_demo_findings.json
```

هتظهر ثغرة `CNAME_NXDOMAIN` — اشرح:
1. الـ CNAME معلّق على اسم مش موجود.
2. الأداة أكدت بخط DNS تاني حقيقي قبل الرفع (قاعدة الفحص مرتين).
3. الـ evidence والـ remediation والمصادر كله في الـ finding.

### الخطوة 5 — التقارير

```powershell
python -m src.cli scan --domain example.com --format all
```

افتح `data\output\report.html` في المتصفح: الكروت، الرسم البياني للخطورة،
تفاصيل كل finding، والـ disclaimer.

---

## ثانيًا: هيكل العرض المقترح (10–12 سلايد)

1. **العنوان والفريق** — اسم المشروع + الأعضاء + المشرف.
2. **المشكلة** — يعني إيه Subdomain Takeover؟ (رسمة `blog.example.com → example.github.io` المعلّقة).
3. **المخاطر** — سرقة cookies، phishing على دومين موثوق، تجاوز CSP/CORS، السمعة.
4. **حجم المشكلة** — أمثلة تقارير منشورة (HackerOne) وإحصائيات الأصول المهجورة.
5. **الحل المقترح** — الـ Pipeline (الرسمة من PROJECT_OVERVIEW §3).
6. **المعمارية التقنية** — الموديولات والـ Data Contracts (docs/architecture.md).
7. **منهجية الكشف** — الكواشف الأربعة + نموذج الثقة/الخطورة + تقليل الـ FPs (docs/methodology.md).
8. **الالتزام الأخلاقي** — detect & report only، تحذير التخويل في الـ CLI، والاختبار على أهداف مصرّح بها فقط.
9. **العرض العملي** — الخطوات الخلق فوق (لقطات شاشة جاهزة + عرض حي لو متاح).
10. **المقارنة بالأدوات الموجودة** — جدول docs/comparison.md.
11. **الاختبارات والجودة** — 130 اختبار، CI على Windows+Ubuntu، lint.
12. **الخلاصة والأعمال المستقبلية** — مصادر مدفوعة (VT/Shodan)، تكامل nuclei، واجهة ويب.

## ثالثًا: أسئلة متوقعة في المناقشة وإجاباتها

| السؤال | الإجابة المختصرة |
|---|---|
| إزاي تضمن إن مفيش false positives؟ | 5 قواعد موثقة: استبعاد الخدمات الآمنة، تجاهل 404 العام من غير بصمة، فحص مرتين قبل الرفع، فلترة الـ wildcard، والنتايج استشارية مع evidence كامل. |
| ليه Python ومش Go زي subjack؟ | قابلية التطوير للفريق، مكتبات نضجة (dnspython/aiohttp)، و cross-platform بدون build خطوات. |
| الأداة بتستغل الثغرة؟ | لأ نهائيًا — مفيش سطر بيعمل claim أو register؛ الـ remediation نصائح بس (Safety check موثق في الخطة). |
| إزاي بتضمن نفس النتايج على Windows وLinux؟ | Resolvers صريحة (مش إعدادات النظام)، pathlib، policy helper للـ event loop، وCI matrix بيشتغل على النظامين. |
| لو خدمة جديدة ظهرت؟ | بنضيف entry في fingerprints.yaml — بدون أي تعديل في الكود. |
| إيه حدود الأداة؟ | موثقة في docs/limitations.md — أهمها: البصمات بتتغير مع الوقت، وMEDIUM مش تأكيد نهائي. |

## رابعًا: تجهيزات قبل يوم المناقشة

- [ ] خد لقطات شاشة للتشغيلات الخمسة (PowerShell + التقرير HTML).
- [ ] جرّب العرض مرة كاملة بتوقيت (المستهدف 10–15 دقيقة).
- [ ] تأكد إن الـ venv شغال على جهاز العرض (أو استخدم `scripts\setup.ps1` من الأول).
- [ ] اختياري: شغّل المشروع مرة على Kali VM وسجّل النتيجة (المرحلة 4 حطت ده كخطوة يدوية متبقية).
