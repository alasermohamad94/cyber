import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { severityBadgeClass } from '../utils/cds';

const STATUS_LABELS: Record<string, string> = {
  open: 'مفتوحة',
  investigating: 'قيد التحقيق',
  pending_approval: 'بانتظار الموافقة',
  resolved: 'محلولة',
};

export default function Incidents() {
  const { hasPermission } = useAuth();
  const [incidents, setIncidents] = useState<Record<string, unknown>[]>([]);
  const [filter, setFilter] = useState('');
  const [selected, setSelected] = useState<Record<string, unknown> | null>(null);
  const [playbooks, setPlaybooks] = useState<Record<string, unknown>[]>([]);

  const load = () => {
    api.listIncidents(filter ? { status: filter } : undefined).then((d) => setIncidents(d.incidents));
    api.listPlaybooks().then((d) => setPlaybooks(d.playbooks)).catch(() => {});
  };

  useEffect(() => {
    load();
    const id = setInterval(load, 10000);
    return () => clearInterval(id);
  }, [filter]);

  const openDetail = async (id: string) => {
    const inc = await api.getIncident(id);
    setSelected(inc);
  };

  const updateStatus = async (status: string) => {
    if (!selected || !hasPermission('incidents:write')) return;
    await api.updateIncident(String(selected.incident_id), { status });
    load();
    openDetail(String(selected.incident_id));
  };

  const runPlaybook = async (playbookId: string) => {
    if (!selected || !hasPermission('playbook:trigger')) return;
    await api.executePlaybook(playbookId, {
      entity_id: selected.target_entity,
      source_ip: selected.source_ip,
      severity: selected.severity,
    });
    alert('تم تشغيل دليل الاستجابة');
  };

  return (
    <div>
      <div className="cds-page-hero mb-4">
        <h2><i className="fas fa-exclamation-triangle me-2" />منصة إدارة الحوادث</h2>
        <p>تتبع دورة حياة الحوادث: مفتوحة → قيد التحقيق → بانتظار الموافقة → محلولة</p>
      </div>

      <div className="row g-3">
        <div className="col-lg-7">
          <div className="cds-card">
            <div className="cds-card-header d-flex justify-content-between align-items-center">
              <span>الحوادث الأمنية</span>
              <select className="form-select form-select-sm w-auto" value={filter} onChange={(e) => setFilter(e.target.value)}>
                <option value="">كل الحالات</option>
                {Object.entries(STATUS_LABELS).map(([k, v]) => (
                  <option key={k} value={k}>{v}</option>
                ))}
              </select>
            </div>
            <div className="table-responsive">
              <table className="table cds-table mb-0">
                <thead>
                  <tr>
                    <th>العنوان</th>
                    <th>الخطورة</th>
                    <th>الحالة</th>
                    <th>الهدف</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {incidents.map((inc) => (
                    <tr key={String(inc.incident_id)}>
                      <td>{String(inc.title)}</td>
                      <td><span className={severityBadgeClass(String(inc.severity))}>{String(inc.severity)}</span></td>
                      <td>{STATUS_LABELS[String(inc.status)] || String(inc.status)}</td>
                      <td>{String(inc.target_entity)}</td>
                      <td>
                        <button type="button" className="btn btn-sm btn-outline-primary" onClick={() => openDetail(String(inc.incident_id))}>
                          تفاصيل
                        </button>
                      </td>
                    </tr>
                  ))}
                  {incidents.length === 0 && (
                    <tr><td colSpan={5} className="text-center text-muted">لا توجد حوادث</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <div className="col-lg-5">
          <div className="cds-card">
            <div className="cds-card-header">تفاصيل الحادثة</div>
            <div className="cds-card-body">
              {!selected ? (
                <p className="text-muted">اختر حادثة لعرض التفاصيل</p>
              ) : (
                <>
                  <h5>{String(selected.title)}</h5>
                  <p><strong>المصدر:</strong> {String(selected.source_ip || '—')}</p>
                  <p><strong>الملاحظات:</strong> {String(selected.notes || '—')}</p>
                  {hasPermission('incidents:write') && (
                    <div className="d-flex flex-wrap gap-2 mb-3">
                      {Object.entries(STATUS_LABELS).map(([k, v]) => (
                        <button key={k} type="button" className="btn btn-sm btn-secondary" onClick={() => updateStatus(k)}>{v}</button>
                      ))}
                    </div>
                  )}
                  {hasPermission('playbook:trigger') && playbooks.length > 0 && (
                    <div className="mb-3">
                      <label className="form-label">تشغيل دليل استجابة</label>
                      <div className="d-flex flex-wrap gap-2">
                        {playbooks.map((pb) => (
                          <button key={String(pb.playbook_id)} type="button" className="btn btn-sm btn-warning" onClick={() => runPlaybook(String(pb.playbook_id))}>
                            {String(pb.name)}
                          </button>
                        ))}
                      </div>
                    </div>
                  )}
                  <Link to={`/investigation?entity=${selected.target_entity}`} className="btn btn-sm btn-info">
                    <i className="fas fa-search me-1" />فتح مساحة التحقيق
                  </Link>
                </>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
