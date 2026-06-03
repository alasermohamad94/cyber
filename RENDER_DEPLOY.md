# نشر على Render (مجاني)

## 1. رفع الكود إلى GitHub

المستودع: `https://github.com/alasermohamad94/cyber`

بعد كل `git push` على فرع `main` يمكن لـ Render إعادة النشر تلقائياً.

## 2. ربط Render

1. ادخل [dashboard.render.com](https://dashboard.render.com)
2. **New** → **Blueprint** (أو **Web Service**)
3. اربط حساب GitHub واختر مستودع `alasermohamad94/cyber`
4. إن استخدمت Blueprint: Render يقرأ `render.yaml` من الجذر
5. فعّل **Auto-Deploy** على فرع `main`

## 3. إعدادات يدوية (بدون Blueprint)

| الحقل | القيمة |
|--------|--------|
| Root Directory | `web_dashboard` |
| Build Command | `pip install -r requirements.txt` |
| Start Command | `gunicorn --bind 0.0.0.0:$PORT --worker-class gthread --threads 4 --timeout 120 wsgi:application` |

**Environment Variables:**

| المتغير | القيمة |
|---------|--------|
| `CDS_BIND_HOST` | `0.0.0.0` |
| `CDS_SECRET_KEY` | سلسلة عشوائية طويلة |
| `CDS_ADMIN_PASSWORD` | كلمة مرور قوية |
| `CDS_CORS_ORIGINS` | `https://YOUR-SERVICE.onrender.com` |
| `CDS_FIREWALL_ENABLED` | `false` |

## 4. بعد النشر

- الرابط: `https://<اسم-الخدمة>.onrender.com/login`
- سجّل الدخول بـ `admin` وكلمة المرور من `CDS_ADMIN_PASSWORD` في Render → Environment

## 5. إذا لم يتحدث الموقع

- Render → خدمتك → **Manual Deploy** → **Deploy latest commit**
- تأكد أن الفرع المربوط هو `main` وليس فرعاً قديماً
- راجع **Logs** عند فشل البناء
