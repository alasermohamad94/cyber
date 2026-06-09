import { FormEvent, useEffect, useRef, useState } from 'react';
import { api } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { CDS_COLORS, initChartDefaults, severityBadgeClass } from '../utils/cds';

type BlockedIp = { ip_address: string; reason: string; blocked_at_formatted?: string; status?: string };
type ThreatEvent = { description: string; severity: string; event_type: string; source_ip?: string };

export default function ThreatManagement() {
  const { hasPermission } = useAuth();
  const [overview, setOverview] = useState<Record<string, unknown> | null>(null);
  const [ip, setIp] = useState('');
  const [reason, setReason] = useState('manual_block');
  const [message, setMessage] = useState('');
  const distRef = useRef<HTMLCanvasElement>(null);
  const distChart = useRef<ChartInstance | null>(null);
  const blockModalRef = useRef<HTMLDivElement>(null);

  const load = () => api.threatOverview().then(setOverview).catch(console.error);

  useEffect(() => {
    initChartDefaults();
    if (distRef.current && typeof Chart !== 'undefined') {
      distChart.current = new Chart(distRef.current.getContext('2d')!, {
        type: 'pie',
        data: {
          labels: ['low', 'medium', 'high', 'critical'],
          datasets: [{ data: [0, 0, 0, 0], backgroundColor: Object.values(CDS_COLORS.severity) }],
        },
        options: { responsive: true, maintainAspectRatio: false },
      });
    }
    load();
    const id = setInterval(load, 8000);
    return () => {
      clearInterval(id);
      distChart.current?.destroy();
    };
  }, []);

  useEffect(() => {
    const risk = overview?.risk_distribution as Record<string, number> | undefined;
    if (distChart.current && risk) {
      distChart.current.data.datasets[0].data = [risk.low, risk.medium, risk.high, risk.critical];
      distChart.current.update();
    }
  }, [overview]);

  const showBlockModal = () => {
    const el = blockModalRef.current;
    if (el) bootstrap.Modal.getOrCreateInstance(el).show();
  };

  const blockIp = async (e: FormEvent) => {
    e.preventDefault();
    if (!hasPermission('ip:block')) return;
    try {
      await api.blockIp(ip, reason);
      setMessage(`تم حظر ${ip}`);
      setIp('');
      bootstrap.Modal.getInstance(blockModalRef.current)?.hide();
      load();
    } catch (err) {
      setMessage(String(err));
    }
  };

  const unblock = async (address: string) => {
    if (!hasPermission('ip:unblock')) return;
    await api.unblockIp(address);
    load();
  };

  const highEvents = (overview?.high_risk_events as ThreatEvent[]) || [];
  const blocked = (overview?.blocked_ips as BlockedIp[]) || [];
  const timeline = (overview?.timeline as { description: string; time_formatted: string; severity: string }[]) || [];

  return (
    <>
      <div className="cds-page-hero">
        <div>
          <h2><i className="fas fa-shield-virus" /> مركز إدارة التهديدات</h2>
          <p>بيانات حية من التخزين والمحرك — حظر IP للمدير فقط (P0)</p>
        </div>
        <div className="cds-hero-actions">
          <button type="button" className="btn btn-light btn-sm" onClick={load}>
            <i className="fas fa-radar" /> تحديث المسح
          </button>
          {hasPermission('ip:block') && (
            <button type="button" className="btn btn-warning btn-sm" onClick={showBlockModal}>
              <i className="fas fa-ban" /> حظر IP
            </button>
          )}
        </div>
      </div>

      {message && <div className="alert alert-info">{message}</div>}

      <div className="cds-kpi-grid mb-4">
        <div className="cds-kpi">
          <div className="cds-kpi-icon" style={{ color: '#6b1f2a' }}><i className="fas fa-exclamation-circle" /></div>
          <div className="cds-kpi-value">{Number(overview?.active_threats ?? 0)}</div>
          <div className="cds-kpi-label">تهديدات نشطة</div>
        </div>
        <div className="cds-kpi">
          <div className="cds-kpi-icon gold"><i className="fas fa-ban" /></div>
          <div className="cds-kpi-value">{Number(overview?.blocked_ips_count ?? 0)}</div>
          <div className="cds-kpi-label">عناوين محظورة</div>
        </div>
        <div className="cds-kpi">
          <div className="cds-kpi-icon"><i className="fas fa-user-shield" /></div>
          <div className="cds-kpi-value">{Number(overview?.isolated_systems ?? 0)}</div>
          <div className="cds-kpi-label">أنظمة معزولة</div>
        </div>
        <div className="cds-kpi">
          <div className="cds-kpi-icon"><i className="fas fa-check-double" /></div>
          <div className="cds-kpi-value">{Number(overview?.resolved_today ?? 0)}</div>
          <div className="cds-kpi-label">تم حلها اليوم</div>
        </div>
      </div>

      <div className="row">
        <div className="col-lg-8 mb-4">
          <div className="card">
            <div className="card-header d-flex justify-content-between align-items-center">
              <h5 className="mb-0"><i className="fas fa-fire" /> تهديدات نشطة</h5>
              <button type="button" className="btn btn-sm btn-light" onClick={load}>
                <i className="fas fa-sync-alt" /> تحديث
              </button>
            </div>
            <div className="card-body" style={{ maxHeight: 600, overflowY: 'auto' }}>
              {highEvents.length === 0 ? (
                <p className="text-muted text-center">لا توجد تهديدات نشطة</p>
              ) : (
                highEvents.map((t, i) => (
                  <div key={i} className={`threat-item high-risk p-3 mb-2 border-start border-4`}>
                    <div className="d-flex justify-content-between">
                      <strong>{t.description}</strong>
                      <span className={`badge bg-${severityBadgeClass(t.severity)}`}>{t.severity}</span>
                    </div>
                    <small className="text-muted">{t.source_ip} — {t.event_type}</small>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
        <div className="col-lg-4 mb-4">
          <div className="card mb-4">
            <div className="card-header"><h5 className="mb-0"><i className="fas fa-chart-pie" /> Threat Distribution</h5></div>
            <div className="card-body">
              <div className="chart-container" style={{ height: 200 }}>
                <canvas ref={distRef} />
              </div>
            </div>
          </div>
          <div className="card">
            <div className="card-header"><h5 className="mb-0"><i className="fas fa-history" /> Recent Activity</h5></div>
            <div className="card-body timeline">
              {timeline.map((item, i) => (
                <div key={i} className="mb-2 pb-2 border-bottom">
                  <small className="text-muted">{item.time_formatted}</small>
                  <div>{item.description}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      <div className="row mb-4">
        <div className="col-12">
          <div className="card">
            <div className="card-header d-flex justify-content-between align-items-center">
              <h5 className="mb-0"><i className="fas fa-ban" /> Blocked IP Addresses</h5>
              {hasPermission('ip:block') && (
                <button type="button" className="btn btn-sm btn-light" onClick={showBlockModal}>
                  <i className="fas fa-plus" /> حظر IP
                </button>
              )}
            </div>
            <div className="card-body">
              <div className="table-responsive">
                <table className="table table-hover">
                  <thead>
                    <tr>
                      <th>IP Address</th>
                      <th>Reason</th>
                      <th>Blocked At</th>
                      <th>Status</th>
                      {hasPermission('ip:unblock') && <th>Actions</th>}
                    </tr>
                  </thead>
                  <tbody>
                    {blocked.length === 0 ? (
                      <tr><td colSpan={5} className="text-center text-muted">لا توجد عناوين محظورة</td></tr>
                    ) : (
                      blocked.map((row) => (
                        <tr key={row.ip_address}>
                          <td>{row.ip_address}</td>
                          <td>{row.reason}</td>
                          <td>{row.blocked_at_formatted || '—'}</td>
                          <td><span className="badge bg-danger">{row.status || 'active'}</span></td>
                          {hasPermission('ip:unblock') && (
                            <td>
                              <button type="button" className="btn btn-sm btn-outline-danger" onClick={() => unblock(row.ip_address)}>
                                إلغاء الحظر
                              </button>
                            </td>
                          )}
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      </div>

      {hasPermission('ip:block') && (
        <div className="modal fade" id="blockIPModal" tabIndex={-1} ref={blockModalRef}>
          <div className="modal-dialog">
            <div className="modal-content">
              <div className="modal-header">
                <h5 className="modal-title"><i className="fas fa-ban" /> Block IP Address</h5>
                <button type="button" className="btn-close" data-bs-dismiss="modal" />
              </div>
              <form onSubmit={blockIp}>
                <div className="modal-body">
                  <div className="mb-3">
                    <label className="form-label">IP Address</label>
                    <input className="form-control" value={ip} onChange={(e) => setIp(e.target.value)} required placeholder="192.168.1.100" />
                  </div>
                  <div className="mb-3">
                    <label className="form-label">Reason</label>
                    <input className="form-control" value={reason} onChange={(e) => setReason(e.target.value)} />
                  </div>
                </div>
                <div className="modal-footer">
                  <button type="button" className="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                  <button type="submit" className="btn btn-warning"><i className="fas fa-ban" /> Block IP</button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
