# تقرير ترقية نظام الدفاع السيبراني إلى منصة SOC

**التاريخ:** 11 يونيو 2026  
**المراجع:** `تقرير الترقية.txt` · `soc_upgrade_plan_ar.pdf` · `مهام الفريق الأزرق.pdf`  
**حالة الاختبارات:** 46 اختباراً ناجحاً بعد التكامل

---

## 1. ملخص تنفيذي

تم ترقية المشروع من نظام دفاع سيبراني إلى **منصة SOC-lite** تشمل: محركات الكشف والقرار، إدارة الحوادث والقضايا، سجلات تدقيق غير قابلة للتلاعب (Hash-chaining)، أدلة استجابة (Playbooks)، وواجهات SOC متكاملة.

ما يعمل **محلياً بالكامل** هو طبقة المنصة البرمجية وقاعدة SQLite. ما يتطلب **بنية تحتية خارجية** (شبكة، سحابة، AD، EDR) مُصمَّم كواجهات جاهزة لكن **لا يُختبر end-to-end** بدون تلك البيئات.

```
┌─────────────────────────────────────────────────────────┐
│  محلي 100%     │  محاكاة/Stub  │  يحتاج بنية خارجية   │
├────────────────┼───────────────┼───────────────────────┤
│ Pipeline أمني  │ Quarantine    │ Cloudflare WAF        │
│ Incidents/Cases│ Forensic snap │ Enterprise FW         │
│ Audit chain    │ Email alerts  │ AD/LDAP disable       │
│ Playbooks      │ GeoIP map     │ NetFlow/IDS/EDR       │
│ RBAC/Sessions  │               │ Real VLAN isolation   │
│ SQLite SOC DB  │               │ Postgres SOC (TODO)   │
└────────────────┴───────────────┴───────────────────────┘
```

---

## 2. ما تم تنفيذه محلياً

### 2.1 طبقة المحركات (Backend)

| المكون | الملف / المسار | الحالة |
|--------|----------------|--------|
| قواعد الإدراك (مسح موزع، تخمين، تسريب) | `perception/behavior_analysis.py` | مُحقَّق مسبقاً |
| محرك السياسات (زمن، أصل، هوية) | `decision_engine/security_policies.py` | **جديد** |
| التصعيد التلقائي (alert → block بعد 10 د) | `decision_engine/escalation.py` | **جديد** |
| الموافقة المزدوجة للأصول الحرجة | `decision_engine/descision_engine.py` + `pending_approvals` | **جديد** |
| استعادة الثقة (24 ساعة + يدوي) | `trust_system/trust_manager.py` | **مُحدَّث** |
| SOAR Playbooks | `response/playbooks.py` | **جديد** |
| Hash-chaining (SHA-256) | `security/audit_chain.py` | **جديد** |
| FirewallProvider (Local / Cloudflare / Enterprise) | `security/firewall_providers.py` | **جديد** |
| IP Block Orchestrator (TTL) | `storage/persistence.py` + `firewall_providers.py` | **جديد** |
| Incident Management | `soc/incident_manager.py` | **جديد** |
| Case Management | `soc/case_manager.py` | **جديد** |
| Query / Replay Engine | `storage/query_engine.py` | **جديد** |
| Session Registry | `security/session_registry.py` | **جديد** |
| RBAC موسَّع | `security/roles.py` | **مُحدَّث** |
| Threat Correlation | `correlation/threat_correlation.py` | مُحقَّق مسبقاً |
| Risk Scoring Engine | `trust_system/trust_manager.py` | مُحقَّق مسبقاً |

### 2.2 قاعدة البيانات — جداول SOC الجديدة

| الجدول | الغرض |
|--------|-------|
| `security_incidents` | دورة حياة الحوادث (open → investigating → pending_approval → resolved) |
| `security_cases` | دمج حوادث متعددة في قضية تحقيق |
| `audit_log_chain` | سجل تدقيق مرتبط بـ SHA-256 |
| `pending_approvals` | موافقات مزدوجة للعمليات الحساسة |
| `quarantine_records` | سجل العزل الافتراضي |
| `active_sessions` | مراقبة وإلغاء جلسات المحللين |
| `escalation_watches` | متابعة التصعيد التلقائي |
| `blocked_ips` (+ TTL) | حظر IPs مع `provider`, `ttl_seconds`, `expires_at` |

### 2.3 واجهات API الجديدة

| Endpoint | الوصف |
|----------|-------|
| `GET /api/soc/command-center` | لوحة قيادة SOC الموحدة |
| `GET/POST/PATCH /api/incidents` | إدارة الحوادث |
| `POST /api/incidents/from-event/{id}` | إنشاء حادثة بنقرة واحدة |
| `GET/POST /api/cases` | إدارة القضايا |
| `POST /api/events/query` | استعلام مركّب |
| `POST /api/forensics/replay` | إعادة تمثيل الأحداث |
| `GET /api/audit/verify` | التحقق من سلامة Hash Chain |
| `GET/POST /api/playbooks` | أدلة الاستجابة |
| `POST /api/firewall/block` | حظر IP عبر مزود مختار |
| `GET /api/quarantine` | الأجهزة المعزولة |
| `GET/POST /api/approvals` | الموافقات المعلقة |
| `GET /api/sessions` | الجلسات النشطة |
| `GET /api/entities/trust` | مركز الثقة |
| `GET /api/soc/realtime-events` | بث الأحداث الحي |

### 2.4 واجهات المستخدم (Frontend)

| الصفحة | المسار | الوصف |
|--------|--------|-------|
| مركز SOC | `/` | Threat Level + إحصائيات حوادث + سلامة التدقيق |
| إدارة الحوادث | `/incidents` | جدول + تفاصيل + playbooks + تحقيق |
| مركز الثقة | `/entities` | حساسية الأصول + سجل السلوك |
| المراقبة الفورية | `/monitor` | بث حي + تنبيهات |
| جدار الحماية | `/firewall` | حظر + عزل + موافقات + TTL |
| التحليل الجنائي | `/replay` | خط زمني + Play/Pause/Speed |
| مساحة التحقيق | `/investigation` | قضايا + رسم بياني + خط زمني |
| الإعدادات | `/settings` | صلاحيات + جلسات + تحقق Hash |

### 2.5 الصلاحيات الجديدة (RBAC)

| الصلاحية | الأدوار |
|----------|---------|
| `incidents:read` | admin, analyst, viewer |
| `incidents:write` | admin, analyst |
| `cases:read/write` | admin, analyst |
| `playbook:trigger` | admin, analyst |
| `audit:verify` | admin, analyst |
| `sessions:manage` | admin |
| `approvals:manage` | admin |
| `quarantine:manage` | admin, analyst |

---

## 3. تقرير: ما لا يمكن تطويره/اختباره محلياً بالكامل

### 3.1 تكامل Cloudflare WAF (Render)

| البند | السبب |
|-------|--------|
| حظر IP سحابي حقيقي | يحتاج `CLOUDFLARE_API_TOKEN` + `CLOUDFLARE_ZONE_ID` + Zone فعّالة على Cloudflare |
| إلغاء الحظر | يحتاج Rule ID من API حي — غير مُنفَّذ بدون بيئة حقيقية |
| حماية خوادم Render | Render + Cloudflare خارج الشبكة المحلية |

**ما يعمل محلياً:** الواجهة `CloudflareWAFProvider` + تسجيل الحظر في DB + عرض "غير متاح" في الواجهة.

---

### 3.2 Enterprise Firewall API

| البند | السبب |
|-------|--------|
| Cisco / Palo Alto / Fortinet API | لا أجهزة شبكية حقيقية ولا `ENTERPRISE_FW_API_URL` |
| قواعد ACL على Router/Switch | يحتاج SNMP/SSH/API للأجهزة |

**ما يعمل محلياً:** Stub يُرجع رسالة "يتطلب endpoint حي".

---

### 3.3 العزل الشبكي الحقيقي (Virtual Quarantine)

| البند | السبب |
|-------|--------|
| VLAN معزولة | يحتاج Switch يدعم 802.1Q + NAC |
| قطع egress فعلي | يحتاج firewall/perimeter حقيقي |
| تعطيل حسابات AD/LDAP | يحتاج Domain Controller + صلاحيات |

**ما يعمل محلياً:** سجل `quarantine_records` + simulate في Playbooks — **لا عزل شبكي فعلي**.

---

### 3.4 جدار الحماية المحلي (netsh / iptables)

| البند | السبب |
|-------|--------|
| `netsh advfirewall` على Windows | يحتاج **صلاحيات Administrator** |
| `iptables` على Linux | يحتاج root / CAP_NET_ADMIN |
| Docker / WSL | قد لا يصل لجدول iptables المضيف |

**ما يعمل محلياً:** تسجيل الحظر في DB + `firewall_applied: false` عند الفشل.

---

### 3.5 التحليل الجنائي المتقدم

| البند | السبب |
|-------|--------|
| Forensic Memory Snapshot | يحتاج EDR/agent على الجهاز المصاب + Volatility |
| Disk Imaging | يحتاج وصول فизي/SSH للأصل |
| Packet Capture (PCAP) | يحتاج SPAN/TAP أو agent شبكي |

**ما يعمل محلياً:** Replay من `security_events` + audit chain — **لا snapshot ذاكرة حقيقي**.

---

### 3.6 التنبيهات الخارجية

| البند | السبب |
|-------|--------|
| Email / SMS / PagerDuty | يحتاج SMTP / Twilio / PagerDuty API + credentials |
| SIEM (Splunk / ELK) | يحتاج cluster خارجي |
| Webhook SOC خارجي | يحتاج endpoint عام |

**ما يعمل محلياً:** WebSocket + `monitor.alerts` + UI فورية.

---

### 3.7 بيانات الشبكة الحية

| البند | السبب |
|-------|--------|
| NetFlow / sFlow / IPFIX | يحتاج collectors + routers |
| IDS/IPS (Snort / Suricata) | يحتاج mirror port + sensors |
| EDR telemetry | يحتاج agents على endpoints |
| GeoIP دقيق | يحتاج MaxMind DB أو API (التطبيق يستخدم IP فقط) |

**ما يعمل محلياً:** تحليل `entity_data` المُمرَّر عبر API + psutil للخادم المحلي.

---

### 3.8 PostgreSQL في الإنتاج

| البند | السبب |
|-------|--------|
| جداول SOC على Postgres | `postgres_store.py` **لم يُحدَّث** بجداول SOC الجديدة |
| Render PostgreSQL | يحتاج `CDS_DATABASE_URL` + deploy |

**ما يعمل محلياً:** SQLite كامل مع كل الجداول. **Postgres:** الجداول القديمة فقط حتى يُحدَّث `postgres_store.py`.

---

### 3.9 الموافقة المزدوجة — قيد جزئي

| البند | السبب |
|-------|--------|
| تنفيذ isolate/block بعد موافقتين | يحتاج admin ثانٍ مسجّل + workflow UI كامل |
| التحقق من كلمة المرور في UI | الواجهة تطلبها لكن **لا تُتحقَّق** من الخادم بعد |

**ما يعمل محلياً:** جدول approvals + API + عرض في `/firewall`.

---

### 3.10 إلغاء الجلسة الفوري

| البند | السبب |
|-------|--------|
| Revoke cookie نشط | Starlette sessions في الذاكرة — revoke في DB **لا يقطع** الجلسة حتى middleware يتحقق |

**ما يعمل محلياً:** تسجيل revoke + عرض في Settings — **يحتاج middleware** للتحقق من `is_session_revoked` على كل طلب.

---

## 4. مقارنة بالخطة الأصلية (تقرير الترقية.txt)

| القسم | نسبة الإنجاز المحلي |
|-------|---------------------|
| §2أ — تحصين الإدراك | ~90% |
| §2ب — محرك السياسات | ~75% (تصعيد + موافقة مزدوجة مُضافة) |
| §2ج — Risk Scoring | ~85% (استعادة الثقة مُضافة) |
| §2د — SOAR-lite | ~60% (playbooks + simulate quarantine) |
| §3أ — Incident & Correlation | ~80% |
| §3ب — Audit & Forensics | ~70% (hash chain + replay؛ لا snapshot حي) |
| §3ج — Access & Governance | ~65% (RBAC + sessions؛ revoke جزئي) |
| §3د — Orchestration | ~50% (Local FW + stubs خارجية) |
| §4 — واجهات SOC | ~85% |

---

## 5. خطوات التشغيل المحلي

```powershell
# Backend
cd c:\Users\ROG\Desktop\cyber-defense-system\cyber-defense-system
python -m uvicorn backend.main:app --reload

# Frontend (terminal آخر)
cd frontend
npm run dev
```

---

## 6. متغيرات البيئة للتكامل الخارجي (اختياري)

```env
CLOUDFLARE_API_TOKEN=...
CLOUDFLARE_ZONE_ID=...
ENTERPRISE_FW_API_URL=...
ENTERPRISE_FW_API_KEY=...
CDS_DATABASE_URL=postgresql://...   # للإنتاج على Render
```

---

## 7. التوصيات للمرحلة التالية

1. **تحديث `postgres_store.py`** بجداول SOC — ضروري لـ Render.
2. **Middleware للجلسات المُلغاة** — لجعل revoke فورياً.
3. **Cloudflare credentials** على Render للحظر السحابي.
4. **EDR agent أو NetFlow collector** لبيانات شبكية حقيقية.
5. **SMTP** لإشعارات البريد في Playbooks.
6. **التحقق من كلمة المرور** في العمليات الحساسة (server-side).

---

## 8. الخلاصة

المنصة أصبحت **SOC-lite** كاملة محلياً: حوادث، قضايا، تدقيق، playbooks، وواجهات متخصصة.  
ما يتطلب **بنية تحتية خارجية** مُصمَّم كواجهات جاهزة (`FirewallProvider`, Playbooks, Quarantine) لكن **لا يُختبر end-to-end** بدون Cloudflare، أجهزة شبكية، AD، أو EDR.

---

*تم إعداد هذا التقرير آلياً بعد تنفيذ ترقية SOC — يونيو 2026*
