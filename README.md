# Cyber Defense System

نظام دفاع سيبراني لمراقبة التهديدات وتحليل السلوك والاستجابة الآلية.

**التقرير الكامل:** [`تقرير_النظام.md`](تقرير_النظام.md)

## المكدس

| الطبقة | التقنية |
|--------|---------|
| Backend | FastAPI |
| Database | PostgreSQL |
| Frontend | React + TypeScript |

## البدء السريع

```bash
# 1. البيئة
cp .env.example .env

# 2. PostgreSQL (اختياري — بدونه يُستخدم SQLite)
docker compose up -d postgres

# 3. Backend
pip install -r requirements.txt
python -m backend.main

# 4. Frontend
cd frontend && npm install && npm run dev
```

- الواجهة: http://localhost:5173  
- API: http://127.0.0.1:8080  

**الدخول الافتراضي:** `admin` / `changeme`

## الاختبارات

```bash
python -m pytest tests/ -v
```

## هيكل المشروع

```
backend/          FastAPI API
frontend/         React UI
perception/       تحليل السلوك
prediction/       التنبؤ + ML shadow
decision_engine/  اتخاذ القرار
trust_system/     درجات الثقة
response/         الاستجابة الآلية
security/         RBAC وجدار ناري
storage/          PostgreSQL / SQLite
```

## الترخيص

مشروع تعليمي/تجريبي — استخدمه وفق القوانين المعمول بها.
