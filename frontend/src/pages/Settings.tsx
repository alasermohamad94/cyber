import { useEffect, useState } from 'react';
import { useAuth } from '../context/AuthContext';

export default function Settings() {
  const { session, hasPermission } = useAuth();
  const [contract, setContract] = useState<unknown[]>([]);

  useEffect(() => {
    fetch(`${import.meta.env.VITE_API_URL || ''}/api/metrics-contract`, { credentials: 'include' })
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => d?.contract && setContract(d.contract))
      .catch(() => {});
  }, []);

  return (
    <>
      <div className="cds-page-hero">
        <div>
          <h2><i className="fas fa-cog" /> إعدادات النظام</h2>
          <p>مرجع التقرير: P0 أمان · P1 عقد المقاييس · P2 التخزين الدائم</p>
        </div>
        <div className="cds-hero-actions">
          {hasPermission('settings:write') ? (
            <button type="button" className="btn btn-light btn-sm">
              <i className="fas fa-save" /> حفظ
            </button>
          ) : (
            <span className="badge bg-secondary">عرض فقط — التعديل للمدير</span>
          )}
        </div>
      </div>

      <div className="container-fluid px-0">
        <ul className="nav nav-tabs mb-4" role="tablist">
          <li className="nav-item">
            <button className="nav-link active" data-bs-toggle="tab" data-bs-target="#general" type="button">
              <i className="fas fa-cog" /> General
            </button>
          </li>
          <li className="nav-item">
            <button className="nav-link" data-bs-toggle="tab" data-bs-target="#security" type="button">
              <i className="fas fa-shield-alt" /> Security
            </button>
          </li>
          <li className="nav-item">
            <button className="nav-link" data-bs-toggle="tab" data-bs-target="#metrics" type="button">
              <i className="fas fa-database" /> Metric Contract
            </button>
          </li>
        </ul>

        <div className="tab-content">
          <div className="tab-pane fade show active" id="general">
            <div className="row">
              <div className="col-lg-6">
                <div className="card">
                  <div className="card-header"><h5 className="mb-0"><i className="fas fa-info-circle" /> System Information</h5></div>
                  <div className="card-body">
                    <div className="mb-3">
                      <label className="form-label">System Name</label>
                      <input type="text" className="form-control" defaultValue="Cyber Defense System" readOnly={!hasPermission('settings:write')} />
                    </div>
                    <div className="mb-3">
                      <label className="form-label">المستخدم الحالي</label>
                      <input type="text" className="form-control" value={session?.username || ''} readOnly />
                    </div>
                    <div className="mb-3">
                      <label className="form-label">الدور</label>
                      <input type="text" className="form-control" value={session?.role || ''} readOnly />
                    </div>
                  </div>
                </div>
              </div>
              <div className="col-lg-6">
                <div className="card">
                  <div className="card-header"><h5 className="mb-0"><i className="fas fa-layer-group" /> Tech Stack</h5></div>
                  <div className="card-body">
                    <ul className="list-group list-group-flush">
                      <li className="list-group-item">Backend: FastAPI</li>
                      <li className="list-group-item">Database: PostgreSQL</li>
                      <li className="list-group-item">Frontend: React + TypeScript</li>
                    </ul>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="tab-pane fade" id="security">
            <div className="card">
              <div className="card-header"><h5 className="mb-0"><i className="fas fa-key" /> الصلاحيات</h5></div>
              <div className="card-body">
                <div className="d-flex flex-wrap gap-2">
                  {(session?.permissions || []).map((p) => (
                    <span key={p} className="badge bg-primary">{p}</span>
                  ))}
                </div>
              </div>
            </div>
          </div>

          <div className="tab-pane fade" id="metrics">
            <div className="card">
              <div className="card-header"><h5 className="mb-0"><i className="fas fa-table" /> Metric Contract</h5></div>
              <div className="card-body table-responsive">
                <table className="table table-sm table-hover">
                  <thead>
                    <tr><th>Name</th><th>Source</th><th>Endpoint</th><th>Precision</th></tr>
                  </thead>
                  <tbody>
                    {(contract as { name: string; source: string; endpoint: string; precision: string }[]).map((row) => (
                      <tr key={row.name}>
                        <td><code>{row.name}</code></td>
                        <td>{row.source}</td>
                        <td><code>{row.endpoint}</code></td>
                        <td>{row.precision}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
