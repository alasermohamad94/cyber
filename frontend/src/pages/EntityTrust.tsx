import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { severityBadgeClass } from '../utils/cds';

export default function EntityTrust() {
  const { hasPermission } = useAuth();
  const [entities, setEntities] = useState<Record<string, unknown>[]>([]);
  const [selected, setSelected] = useState<Record<string, unknown> | null>(null);

  useEffect(() => {
    api.entityTrust().then((d) => setEntities(d.entities)).catch(console.error);
    const id = setInterval(() => api.entityTrust().then((d) => setEntities(d.entities)), 12000);
    return () => clearInterval(id);
  }, []);

  return (
    <div>
      <div className="cds-page-hero mb-4">
        <h2><i className="fas fa-fingerprint me-2" />مركز إدارة الكيانات ونقاط الثقة</h2>
        <p>تصنيف حساسية الأصول، سجل السلوك، ومستوى التهديد لكل جهاز</p>
      </div>

      <div className="row g-3">
        <div className="col-lg-8">
          <div className="cds-card">
            <div className="table-responsive">
              <table className="table cds-table mb-0">
                <thead>
                  <tr>
                    <th>الكيان</th>
                    <th>نوع الأصل</th>
                    <th>الثقة</th>
                    <th>المخاطر</th>
                    <th>الاتجاه</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {entities.map((e) => (
                    <tr key={String(e.entity_id)} className={selected?.entity_id === e.entity_id ? 'table-active' : ''}>
                      <td><code>{String(e.entity_id)}</code></td>
                      <td>{String(e.asset_label || e.asset_type)} <small className="text-muted">×{String(e.asset_criticality)}</small></td>
                      <td>
                        <div className="progress" style={{ height: 8, minWidth: 80 }}>
                          <div className="progress-bar bg-success" style={{ width: `${Number(e.trust_score)}%` }} />
                        </div>
                        <small>{Number(e.trust_score).toFixed(0)}</small>
                      </td>
                      <td><span className={severityBadgeClass(String(e.risk_level))}>{String(e.risk_level)} ({Number(e.risk_score).toFixed(0)})</span></td>
                      <td>{String(e.trust_trend)}</td>
                      <td>
                        <button type="button" className="btn btn-sm btn-outline-secondary" onClick={() => setSelected(e)}>عرض</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <div className="col-lg-4">
          {selected && (
            <div className="cds-card">
              <div className="cds-card-header">{String(selected.entity_id)}</div>
              <div className="cds-card-body">
                <p><strong>آخر حادث:</strong> {String(selected.last_incident_type)} ({String(selected.last_incident_severity)})</p>
                <p><strong>تاريخ السلوك:</strong></p>
                <div className="d-flex gap-1 flex-wrap">
                  {(selected.behavior_history as number[] || []).map((s, i) => (
                    <span key={i} className={`badge ${s >= 70 ? 'bg-danger' : s >= 40 ? 'bg-warning' : 'bg-success'}`}>{s.toFixed(0)}</span>
                  ))}
                </div>
                <Link to={`/replay?entity=${selected.entity_id}`} className="btn btn-sm btn-primary mt-3 me-2">
                  إعادة تمثيل الأحداث
                </Link>
                <Link to={`/investigation?entity=${selected.entity_id}`} className="btn btn-sm btn-info mt-3">
                  التحقيق
                </Link>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
