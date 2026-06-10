import { useEffect, useState } from 'react';
import { api } from '../api/client';
import { severityBadgeClass } from '../utils/cds';

export default function RealTimeMonitor() {
  const [events, setEvents] = useState<Record<string, unknown>[]>([]);
  const [alerts, setAlerts] = useState<Record<string, unknown>[]>([]);
  const [metrics, setMetrics] = useState({ cpu: 0, memory: 0, connections: 0 });

  useEffect(() => {
    const load = () => {
      api.realtimeEvents().then((d) => {
        setEvents(d.events || []);
        setAlerts(d.alerts || []);
      });
      api.systemMetrics().then((m) =>
        setMetrics({
          cpu: Number(m.cpu_percent) || 0,
          memory: Number(m.memory_percent) || 0,
          connections: Number(m.active_connections) || 0,
        })
      );
    };
    load();
    const id = setInterval(load, 3000);
    return () => clearInterval(id);
  }, []);

  return (
    <div>
      <div className="cds-page-hero mb-4">
        <h2><i className="fas fa-broadcast-tower me-2" />المراقبة الأمنية الفورية</h2>
        <p>بث حي للأحداث والتنبيهات — مناسب لشاشات SOC</p>
      </div>

      <div className="row g-3 mb-4 cds-rtm-kpis">
        <div className="col-md-4"><div className="cds-kpi"><span>CPU</span><strong>{metrics.cpu.toFixed(1)}%</strong></div></div>
        <div className="col-md-4"><div className="cds-kpi"><span>الذاكرة</span><strong>{metrics.memory.toFixed(1)}%</strong></div></div>
        <div className="col-md-4"><div className="cds-kpi"><span>الاتصالات</span><strong>{metrics.connections}</strong></div></div>
      </div>

      {alerts.length > 0 && (
        <div className="alert alert-danger mb-3">
          <i className="fas fa-bell me-2" />
          {String((alerts[alerts.length - 1] as Record<string, unknown>).message)}
        </div>
      )}

      <div className="cds-card">
        <div className="cds-card-header">بث الأحداث</div>
        <div className="cds-event-stream" style={{ maxHeight: 500, overflow: 'auto' }}>
          {[...events].reverse().map((ev) => (
            <div key={String(ev.event_id)} className={`cds-event-item cds-sev-${ev.severity} p-2 border-bottom`}>
              <span className={severityBadgeClass(String(ev.severity))}>{String(ev.severity)}</span>
              <span className="ms-2 text-muted">{String(ev.time_formatted)}</span>
              <span className="ms-2">{String(ev.description)}</span>
              <small className="d-block text-muted">{String(ev.source_ip)} → {String(ev.target_entity)}</small>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
