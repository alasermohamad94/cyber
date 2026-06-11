import { FormEvent, useEffect, useState } from 'react';
import { api } from '../api/client';
import { useAuth } from '../context/AuthContext';

type SensitiveAction = {
  kind: 'block_ip' | 'release_quarantine' | 'approve_action';
  target: string;
  risk: 'medium' | 'high' | 'critical';
  run: () => Promise<void>;
};

export default function FirewallPanel() {
  const { hasPermission } = useAuth();
  const [providers, setProviders] = useState<Record<string, unknown>[]>([]);
  const [blocked, setBlocked] = useState<Record<string, unknown>[]>([]);
  const [quarantine, setQuarantine] = useState<Record<string, unknown>[]>([]);
  const [approvals, setApprovals] = useState<Record<string, unknown>[]>([]);
  const [ip, setIp] = useState('');
  const [reason, setReason] = useState('manual_block');
  const [provider, setProvider] = useState('local_os');
  const [ttl, setTtl] = useState(3600);
  const [msg, setMsg] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [justification, setJustification] = useState('');
  const [pendingAction, setPendingAction] = useState<SensitiveAction | null>(null);
  const [confirmStep, setConfirmStep] = useState(1);

  const load = () => {
    api.firewallProviders().then((d) => setProviders(d.providers)).catch(() => {});
    api.blockedIps().then((d) => setBlocked(d.blocked_ips)).catch(() => {});
    if (hasPermission('quarantine:manage')) api.listQuarantine().then((d) => setQuarantine(d.quarantine)).catch(() => {});
    if (hasPermission('approvals:manage')) api.listPendingApprovals().then((d) => setApprovals(d.approvals)).catch(() => {});
  };

  useEffect(() => {
    load();
    const id = setInterval(load, 8000);
    return () => clearInterval(id);
  }, [hasPermission]);

  const openConfirmation = (action: SensitiveAction) => {
    setPendingAction(action);
    setConfirmStep(1);
    setConfirmPassword('');
    setJustification('');
  };

  const finishConfirmation = async () => {
    if (!pendingAction) return;
    if (confirmStep === 1) {
      if (!confirmPassword.trim()) {
        setMsg('الخطوة 1: أدخل كلمة مرور المحلل للتأكيد.');
        return;
      }
      setConfirmStep(2);
      return;
    }
    if (confirmStep === 2) {
      if (!justification.trim()) {
        setMsg('الخطوة 2: اكتب التبرير الأمني قبل التنفيذ.');
        return;
      }
      setConfirmStep(3);
      return;
    }
    try {
      await pendingAction.run();
      setMsg(`تم تنفيذ الإجراء الحساس على ${pendingAction.target}`);
      setPendingAction(null);
      load();
    } catch (err) {
      setMsg(String(err));
    }
  };

  const block = async (e: FormEvent) => {
    e.preventDefault();
    if (!hasPermission('ip:block')) {
      setMsg('ليست لديك صلاحية حظر IP');
      return;
    }
    openConfirmation({
      kind: 'block_ip',
      target: ip,
      risk: 'high',
      run: async () => {
        await api.blockIpOrchestrated(ip, reason, provider, ttl);
        setIp('');
      },
    });
  };

  const release = async (qid: string) => {
    openConfirmation({
      kind: 'release_quarantine',
      target: qid,
      risk: 'critical',
      run: async () => {
        await api.releaseQuarantine(qid);
      },
    });
  };

  const approve = async (approvalId: string) => {
    openConfirmation({
      kind: 'approve_action',
      target: approvalId,
      risk: 'critical',
      run: async () => {
        await api.approvePendingAction(approvalId, false);
      },
    });
  };

  const riskWidth = pendingAction?.risk === 'critical' ? '100%' : pendingAction?.risk === 'high' ? '75%' : '50%';

  return (
    <div>
      <div className="cds-page-hero mb-4">
        <h2><i className="fas fa-fire me-2" />لوحة جدار الحماية والاستجابة</h2>
        <p>إدارة الحظر، العزل، والموافقات المعلقة مع تأكيدات أمنية متعددة الخطوات</p>
      </div>

      {msg && <div className="alert alert-info">{msg}</div>}

      {pendingAction && (
        <div className="modal d-block" tabIndex={-1} style={{ background: 'rgba(0,0,0,.45)' }}>
          <div className="modal-dialog modal-lg modal-dialog-centered">
            <div className="modal-content">
              <div className="modal-header">
                <h5 className="modal-title">تأكيد أمني متعدد الخطوات</h5>
                <button type="button" className="btn-close" onClick={() => setPendingAction(null)} />
              </div>
              <div className="modal-body">
                <div className="alert alert-warning">
                  الإجراء: <strong>{pendingAction.kind}</strong> — الهدف: <code>{pendingAction.target}</code>
                </div>
                <label className="form-label">مستوى خطورة الإجراء على استمرارية العمل</label>
                <div className="progress mb-3">
                  <div className="progress-bar progress-bar-striped progress-bar-animated" style={{ width: riskWidth }}>
                    {pendingAction.risk.toUpperCase()}
                  </div>
                </div>

                {confirmStep === 1 && (
                  <div>
                    <label className="form-label">1) كلمة مرور المحلل</label>
                    <input type="password" className="form-control" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} autoFocus />
                  </div>
                )}
                {confirmStep === 2 && (
                  <div>
                    <label className="form-label">2) التبرير الأمني</label>
                    <textarea className="form-control" value={justification} onChange={(e) => setJustification(e.target.value)} placeholder="مثال: نشاط مسح منافذ من IP خارجي ضد خادم ويب حساس" />
                  </div>
                )}
                {confirmStep === 3 && (
                  <div className="alert alert-danger mb-0">
                    3) التأكيد النهائي: سيتم توثيق العملية في سجل التدقيق المشفر. اضغط تنفيذ لإكمال العملية.
                  </div>
                )}
              </div>
              <div className="modal-footer">
                <button type="button" className="btn btn-secondary" onClick={() => setPendingAction(null)}>إلغاء</button>
                <button type="button" className="btn btn-danger" onClick={finishConfirmation}>
                  {confirmStep < 3 ? 'التالي' : 'تنفيذ'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="row g-3">
        <div className="col-lg-5">
          {hasPermission('ip:block') && (
            <div className="cds-card mb-3">
              <div className="cds-card-header">طلب حظر IP</div>
              <form className="cds-card-body" onSubmit={block}>
                <div className="mb-2">
                  <label className="form-label">عنوان IP</label>
                  <input className="form-control" value={ip} onChange={(e) => setIp(e.target.value)} required />
                </div>
                <div className="mb-2">
                  <label className="form-label">سبب الحظر</label>
                  <select className="form-select" value={reason} onChange={(e) => setReason(e.target.value)}>
                    <option value="manual_block">حظر يدوي</option>
                    <option value="brute_force">Brute Force</option>
                    <option value="port_scan">Port Scan</option>
                    <option value="exfiltration">Data Exfiltration</option>
                  </select>
                </div>
                <div className="mb-2">
                  <label className="form-label">المزود</label>
                  <select className="form-select" value={provider} onChange={(e) => setProvider(e.target.value)}>
                    {providers.map((p) => (
                      <option key={String(p.provider_id)} value={String(p.provider_id)} disabled={!p.available}>
                        {String(p.display_name)} {!p.available ? '(غير متاح)' : ''}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="mb-2">
                  <label className="form-label">TTL (ثانية)</label>
                  <input type="number" className="form-control" value={ttl} onChange={(e) => setTtl(Number(e.target.value))} />
                </div>
                <button type="submit" className="btn btn-danger">بدء إجراء الحظر</button>
              </form>
            </div>
          )}

          {hasPermission('approvals:manage') && approvals.length > 0 && (
            <div className="cds-card">
              <div className="cds-card-header">موافقات معلقة</div>
              <ul className="list-group list-group-flush">
                {approvals.map((a) => (
                  <li key={String(a.approval_id)} className="list-group-item">
                    {String(a.action_type)} — {String(a.target_entity || a.target_ip)}
                    <small className="d-block text-muted">طلب من: {String(a.requested_by)}</small>
                    <button type="button" className="btn btn-sm btn-outline-danger mt-2" onClick={() => approve(String(a.approval_id))}>
                      موافقة آمنة
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>

        <div className="col-lg-7">
          <div className="cds-card mb-3">
            <div className="cds-card-header">IPs محظورة</div>
            <table className="table cds-table mb-0">
              <thead><tr><th>IP</th><th>السبب</th><th>المزود</th><th>TTL</th></tr></thead>
              <tbody>
                {blocked.map((b) => (
                  <tr key={String(b.ip_address)}>
                    <td><code>{String(b.ip_address)}</code></td>
                    <td>{String(b.reason)}</td>
                    <td>{String(b.provider || 'local_os')}</td>
                    <td>{b.expires_at ? new Date(Number(b.expires_at) * 1000).toLocaleString() : '—'}</td>
                  </tr>
                ))}
                {blocked.length === 0 && <tr><td colSpan={4} className="text-muted text-center">لا توجد عناوين محظورة</td></tr>}
              </tbody>
            </table>
          </div>

          {hasPermission('quarantine:manage') && (
            <div className="cds-card">
              <div className="cds-card-header">أجهزة معزولة</div>
              <table className="table cds-table mb-0">
                <thead><tr><th>الكيان</th><th>النوع</th><th>الحالة</th><th></th></tr></thead>
                <tbody>
                  {quarantine.map((q) => (
                    <tr key={String(q.quarantine_id)}>
                      <td>{String(q.entity_id)}</td>
                      <td>{String(q.quarantine_type)}</td>
                      <td>{String(q.status)}</td>
                      <td>
                        <button type="button" className="btn btn-sm btn-outline-success" onClick={() => release(String(q.quarantine_id))}>
                          طلب فك العزل الآمن
                        </button>
                      </td>
                    </tr>
                  ))}
                  {quarantine.length === 0 && <tr><td colSpan={4} className="text-muted text-center">لا أجهزة معزولة</td></tr>}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
