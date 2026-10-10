# RDP Recon Bot

> بوت تلغرام لتدقيق منافذ RDP — فحص مفتوح، تحليل بروتوكول، فحص بيانات، كشف ثغرات، وشهادة TLS. مبني على `asyncio` خالص: بلا threads، بلا process pools، بلا تسريب ذاكرة.

<div align="center">

`port scan` · `banner` · `TLS cert` · `BlueKeep` · `credential audit` · `proxy rotation`

</div>

---

## المحتويات

- [نظرة عامة](#نظرة-عامة)
- [الميزات](#الميزات)
- [البنية](#البنية)
- [التشغيل السريع](#التشغيل-السريع)
- [النشر على Railway](#النشر-على-railway)
- [المتغيرات البيئية](#المتغيرات-البيئية)
- [الاستخدام](#الاستخدام)
- [صيغ الملفات](#صيغ-الملفات)
- [الإعدادات](#الإعدادات)
- [المخرجات](#المخرجات)
- [الأداء والضبط](#الأداء-والضبط)
- [الاستكشاف والأخطاء](#الاستكشاف-والأخطاء)
- [ملاحظات أمنية](#ملاحظات-أمنية)

---

## نظرة عامة

`RDP Recon Bot` أداة تدقيق منافذ **3389** على نطاق واسع. تفحص شبكات CIDR كاملة، تكشف المنافذ المفتوحة، تسحب بصمة بروتوكول RDP، تتحقق من شهادات TLS، تفحص heuristic لثغرة BlueKeep، وتختبر بيانات اعتماد معتمدة — كل ذلك عبر واجهة تلغرام.

مصمّمة للتشغيل على موارد محدودة (Railway) بلا حاجة لـ GPU أو RAM عالية. تحت `concurrency=1000` تصل لأكثر من **10,000 IP/دقيقة** من VPS عادي.

---

## الميزات

| الفئة | التفصيل |
|---|---|
| **المسح** | مسح TCP متوازي بـ asyncio، حتى 2000 اتصال متزامن |
| **البصمة** | إرسال RDP Negotiation Request وقراءة `selectedProtocol` |
| **الشهادات** | سحب TLS cert: CN، المُصدر، الصلاحية، SHA-256 |
| **CVE** | فحص BlueKeep (CVE-2019-0708) heuristic — vulnerable / patched / unknown |
| **البيانات** | اختبار credentials عبر `xfreerdp +auth-only` (بلا جلسة تفاعلية) |
| **التخفّي** | دعم SOCKS5 proxy rotation من env `PROXIES` |
| **الاستئناف** | حفظ حالة تلقائي — استئناف بعد توقف أو redeploy |
| **التحكم** | إيقاف / إيقاف مؤقت / استئناف أثناء الفحص |
| **التصدير** | TXT، CSV، JSON — مع BlueKeep و Credentials مدمجين |
| **البحث** | سجل آخر 5 مسوحات مع الإحصاءات |
| **الحماية** | قائمة chat_id مسموحة، توكن عبر env |

---

## البنية

```
rdp-recon-bot/
├── bot.py              # الواجهة: Telegram handlers، إدارة الجلسات
├── scanner.py          # القلب: RDPScanner، منطق المسح الكامل
├── requirements.txt
├── nixpacks.toml       # تبعيات النظام (freerdp) على Railway
├── railway.toml
├── .env.example
├── .gitignore
├── scan_states/        # [مولّد] حالة المسح
└── scan_results/       # [مولّد] نتائج المسح
```

**تدفّق العمل:**

```
Telegram ──▶ bot.py ──▶ RDPScanner.scan()
                           │
                           ├─ producer()  →  queue
                           ├─ worker()×N  →  port probe
                           ├─ enrich()    →  banner / TLS / BlueKeep
                           └─ cred_task() →  xfreerdp +auth-only
                                   │
                                   ▼
                           found_results ──▶ Telegram + disk
```

---

## التشغيل السريع

**المتطلبات:** Python 3.10+، `xfreerdp` (اختياري، فقط لفحص credentials).

```bash
git clone <repo-url>
cd rdp-recon-bot

python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# عدّل .env: ضع التوكن و chat_id

python bot.py
```

**Linux — تثبيت xfreerdp:**
```bash
# Debian/Ubuntu
sudo apt install freerdp2-x11

# Arch
sudo pacman -S freerdp

# macOS
brew install freerdp
```

---

## النشر على Railway

**1. ارفع المشروع لـ GitHub.**

**2. Railway → New Project → Deploy from GitHub → اختر الريبو.**

**3. أضف Volume** (لحفظ النتائج بين deployments):
```
Dashboard → Volumes → New Volume
Mount path: /data
```

**4. أضف Variables:**
```
TELEGRAM_BOT_TOKEN = ضع_التوكن
ALLOWED_CHATS      = chat_id_بتاعك
DATA_DIR           = /data
PROXIES            = (اختياري)
```

**5. Railway يبني تلقائياً** بفضل `nixpacks.toml` (يجيب `freerdp2-x11` معاه).

**ملاحظة:** الخطة المجانية على Railway ما فيهاش Volume دائم. للحفظ بين deployments، استخدم خطة Hobby أو أعلى.

---

## المتغيرات البيئية

| المتغير | إلزامي | الوصف |
|---|---|---|
| `TELEGRAM_BOT_TOKEN` | ✅ | توكن البوت من BotFather |
| `ALLOWED_CHATS` | ⚠️ مُوصى | chat_ids مسموحة، مفصولة بفواصل. فارغ = مفتوح للكل |
| `DATA_DIR` | ❌ | مجلد الحفظ. محلياً `.`، على Railway `/data` |
| `PROXIES` | ❌ | قائمة SOCKS5: `socks5://user:pass@host:port,socks5://...` |

**مثال `.env`:**
```
TELEGRAM_BOT_TOKEN=8971326867:AA...
ALLOWED_CHATS=123456789,987654321
DATA_DIR=.
PROXIES=socks5://user:pass@1.2.3.4:1080
```

---

## الاستخدام

### تشغيل مسح عادي

1. أرسل `/start` → القائمة الرئيسية.
2. أرسل ملف `.txt` فيه نطاقات CIDR:
   ```
   192.168.1.0/24
   10.0.0.0/16
   203.0.113.0/24
   ```
3. البوت يبدأ ويحدّث الحالة كل 2000 IP.
4. عند الاكتمال: تصدير TXT / CSV / JSON.

### فحص credentials

1. أرسل ملف `creds.txt` أولاً:
   ```
   administrator:Password123
   DOMAIN\admin:Summer2024!
   user@local:Welcome1
   ```
2. البوت يأكد التحميل → أرسل ملف النطاقات.
3. أي credential صالحة → **رسالة فورية منفصلة** بالـ IP والبيانات.

### كشف BlueKeep

⚙️ الإعدادات → `BlueKeep: ON` → الفحص يشمل كل IP مفتوح.

### سحب شهادة TLS

⚙️ الإعدادات → `TLS Cert: ON` → كل IP مفتوح يخزّن شهادته.

---

## صيغ الملفات

### ملف النطاقات (`targets.txt`)

```
# تعليق — يُتجاهل
192.168.1.0/24
10.0.0.0/16
# 203.0.113.5/32
```

- سطر واحد لكل شبكة.
- `#` في البداية = تعليق.
- الحد الأقصى **50,000 IP** لكل شبكة (حماية من الأخطاء).

### ملف البيانات (`creds.txt`)

```
user:pass
DOMAIN\user:pass
user@domain:pass
```

- كشف الملف: أي اسم فيه `cred`، أو يبدأ بـ `user` / `pass`.
- فاصل واحد: `:` (آخر `:` يفصل).

---

## الإعدادات

من ⚙️ **الإعدادات** في البوت:

| الإعداد | المدى | الافتراضي | الأثر |
|---|---|---|---|
| **التوازي** | 100 – 2000 | 1000 | اتصالات متزامنة. أعلى = أسرع، أثقل على الشبكة |
| **المهلة** | 0.5s – 5s | 1.0s | وقت انتظار كل IP. أعلى = أدق، أبطأ |
| **Banner** | ON/OFF | ON | سحب بصمة RDP (بروتوكول + OS hint) |
| **BlueKeep** | ON/OFF | OFF | فحص CVE-2019-0708 (يضيف ~1s لكل IP) |
| **TLS Cert** | ON/OFF | OFF | سحب الشهادة (يضيف ~2s لكل IP) |
| **Proxies** | عدد | من env | SOCKS5 للإخفاء أو تجاوز الحجب |

---

## المخرجات

### حقول كل نتيجة

```json
{
  "ip": "203.0.113.5",
  "port": 3389,
  "open": true,
  "protocol": "CredSSP (NLA)",
  "os_hint": "Windows (NLA enforced)",
  "banner": "030000130ed0...",
  "tls_cert": {
    "subject_cn": "SERVER01.domain.local",
    "issuer_cn": "domain-SERVER01-CA",
    "not_before": "Jan  1 00:00:00 2024 GMT",
    "not_after":  "Jan  1 00:00:00 2026 GMT",
    "sha256": "a1b2c3..."
  },
  "bluekeep": "patched",
  "creds": {
    "user": "administrator",
    "password": "Password123"
  },
  "found_at": 1718000000.0
}
```

### التصدير

| الصيغة | المحتوى |
|---|---|
| **TXT** | سطر لكل IP مفتوح فقط |
| **CSV** | IP, Port, Protocol, OS_Hint, BlueKeep, User, Password |
| **JSON** | كامل السجلات بكل الحقول |

### سجل المسح

ملف `scan_results/scan_YYYYMMDD_HHMMSS.json` يُحفظ تلقائياً بعد كل مسح مكتمل. آخر 5 يظهروا في زر 📋 **السجل**.

---

## الأداء والضبط

### تقديرات السرعة (VPS واحد، 4 vCPU)

| التوازي | المهلة | IP/ثانية | 65k IP |
|---|---|---|---|
| 500 | 1.0s | ~2500 | ~26 ثانية |
| 1000 | 1.0s | ~5000 | ~13 ثانية |
| 2000 | 1.0s | ~8000 | ~8 ثوانٍ |

الأرقام تتحرك حسب: عرض النطاق، الـ latency، فقدان الحزم، هل proxies مفعّلة.

### نصائح الضبط

- **شبكة موثوقة** → `timeout=0.5`، `concurrency=1500`.
- **شبكة بعيدة/غير مستقرة** → `timeout=2.0`، `concurrency=500`.
- **مع proxies** → نزّل `concurrency` للنصف — البروكسي عنق زجاجة.
- **Creds** → كل credential = subprocess. مع 20 creds × 100 IP = 2000 عملية. راقب CPU.
- **BlueKeep + TLS + Creds معاً** → بطيء. خلّي `concurrency=300-500`.

### لماذا `xfreerdp +auth-only`؟

`+auth-only` يخلي xfreerdp:
- يعمل مصافحة NLA/TLS كاملة.
- يتحقق من البيانات على DC أو محلياً.
- **يخرج فوراً** بعد النجاح أو الفشل.
- ما يفتح جلسة سطح مكتب (بلا شاشة، بلا X11).

`returncode == 0` = بيانات صحيحة. أي شي آخر = فشل.

---

## الاستكشاف والأخطاء

| المشكلة | السبب | الحل |
|---|---|---|
| `TELEGRAM_BOT_TOKEN missing` | env ما وصلش | Railway → Variables → أعد التحقق |
| `Conflict: terminated by other getUpdates` | instance ثاني شغال | احذف deployment قديم / اطفي البوت المحلي |
| لا نتائج أبداً | الشبكة محجوبة / firewall | جرب `timeout=2.0`، proxies، أو شبكة أقرب |
| BlueKeep دايماً `unknown` | الهدف ما يدعم RDP_NEG | طبيعي على بعض النسخ القديمة — استخدم scanner خارجي للتحقق |
| Creds دايماً فاشلة | `xfreerdp` مش مثبّت | `apt install freerdp2-x11` — على Railway يبني تلقائياً |
| المسح يقطع بعد ~50k IP | hard limit لكل شبكة | قسّم CIDR لشبكات أصغر |
| Railway يقتل البوت بعد دقائق | خطة Free / memory limit | استخدم Hobby، نزّل `concurrency` |
| نتائج مفقودة بعد redeploy | لا يوجد Volume | أضف Volume عند `/data` و `DATA_DIR=/data` |

### فحص السجلات

```bash
# محلياً
python bot.py

# Railway
Deployments → Logs → ابحث عن "bot running"
```

---

## ملاحظات أمنية

### قبل التشغيل

- **لا تكتب التوكن في الكود أبداً.** استخدم `.env` (محلياً) أو Variables (Railway).
- **`ALLOWED_CHATS` فاضي = أي شخص يعثر على البوت يقدر يفحص.** املأها.
- **توكن مكشوف = السيطرة على البوت.** لو انكشف، BotFather → Revoke فوري.

### أثناء التشغيل

- **الجلسة تُخزَّن على القرص** (`scan_states/`) وتحتوي نتائج حساسة. على Railway استخدم Volume خاص.
- **`xfreerdp` يُشغّل subprocess بصلاحيات البوت.** لا تعطِ البوت صلاحيات root.
- **proxies مطلوبة لو الهدف يراقب المصدر.** الفحص بلا proxy = IP البوت مكشوف.

### بصمات الفحص

فحص RDP كامل (خاصة BlueKeep probe) يترك **آثار في سجلات الهدف**:

- **Windows Security Log** — Logon Failure events (Event ID 4625) لكل محاولة cred.
- **Firewall / IDS** — أنماط port scan و BlueKeep signature.
- **RDP Negotiation** — إرسال طلبات متعددة من نفس IP = مشبوه.

### الحدود

هذه الأداة للتدقيق على **شبكات تملكها أو لديك إذن صريح لفحصها**. الفحص بلا تفويض قد يخالف قوانين الوصول غير المصرّح به في بلدك.

---

## الرخصة

استخدام شخصي وتعليمي. المستخدم مسؤول كاملاً عن الاستخدام.

---

<div align="center">

**ابنِ بهدوء. اضرب بدقة.**

</div>
