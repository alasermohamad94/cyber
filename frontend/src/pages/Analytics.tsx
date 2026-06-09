import { useEffect, useRef, useState } from 'react';
import { api } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { CDS_COLORS, initChartDefaults } from '../utils/cds';

export default function Analytics() {
  const { hasPermission } = useAuth();
  const perfRef = useRef<HTMLCanvasElement>(null);
  const resourceRef = useRef<HTMLCanvasElement>(null);
  const eventsRef = useRef<HTMLCanvasElement>(null);
  const threatRef = useRef<HTMLCanvasElement>(null);
  const charts = useRef<ChartInstance[]>([]);

  const [data, setData] = useState<Record<string, unknown> | null>(null);
  const [processes, setProcesses] = useState<{ name: string; pid: number; cpu_percent: number; memory_percent: number }[]>([]);

  useEffect(() => {
    initChartDefaults();
    const mk = (el: HTMLCanvasElement | null, cfg: unknown) => {
      if (!el || typeof Chart === 'undefined') return null;
      const c = new Chart(el.getContext('2d')!, cfg);
      charts.current.push(c);
      return c;
    };

    mk(perfRef.current, {
      type: 'line',
      data: { labels: [], datasets: [
        { label: 'CPU', data: [], borderColor: CDS_COLORS.primary, tension: 0.4 },
        { label: 'Memory', data: [], borderColor: CDS_COLORS.gold, tension: 0.4 },
      ]},
      options: { responsive: true, maintainAspectRatio: false, scales: { y: { max: 100 } } },
    });
    mk(resourceRef.current, {
      type: 'doughnut',
      data: { labels: ['CPU', 'Memory', 'Disk', 'Network'], datasets: [{ data: [0, 0, 0, 0], backgroundColor: CDS_COLORS.chart }] },
      options: { responsive: true, maintainAspectRatio: false },
    });
    mk(eventsRef.current, {
      type: 'bar',
      data: { labels: ['low', 'medium', 'high', 'critical'], datasets: [{ label: 'Events', data: [0, 0, 0, 0], backgroundColor: CDS_COLORS.secondary }] },
      options: { responsive: true, maintainAspectRatio: false },
    });
    mk(threatRef.current, {
      type: 'radar',
      data: { labels: ['low', 'medium', 'high', 'critical'], datasets: [{ label: 'Risk', data: [0, 0, 0, 0], borderColor: CDS_COLORS.gold }] },
      options: { responsive: true, maintainAspectRatio: false },
    });

    const load = async () => {
      const [a, p] = await Promise.all([
        api.analyticsOverview(),
        fetch(`${import.meta.env.VITE_API_URL || ''}/api/processes`, { credentials: 'include' }).then((r) => r.json()),
      ]);
      setData(a);
      setProcesses(p.processes || []);

      const hist = a.performance_history as { labels: string[]; cpu: number[]; memory: number[] };
      if (charts.current[0] && hist?.labels) {
        charts.current[0].data.labels = hist.labels;
        charts.current[0].data.datasets[0].data = hist.cpu || [];
        charts.current[0].data.datasets[1].data = hist.memory || [];
        charts.current[0].update();
      }
      const dist = a.resource_distribution as Record<string, number>;
      if (charts.current[1] && dist) {
        charts.current[1].data.datasets[0].data = [dist.cpu, dist.memory, dist.disk, dist.network];
        charts.current[1].update();
      }
      const ev = a.events_by_severity as Record<string, number>;
      if (charts.current[2] && ev) {
        charts.current[2].data.datasets[0].data = [ev.low, ev.medium, ev.high, ev.critical];
        charts.current[2].update();
      }
      const risk = (a.trust_statistics as { risk_distribution?: Record<string, number> })?.risk_distribution;
      if (charts.current[3] && risk) {
        charts.current[3].data.datasets[0].data = [risk.low, risk.medium, risk.high, risk.critical];
        charts.current[3].update();
      }
    };
    load();
    const id = setInterval(load, 10000);
    return () => {
      clearInterval(id);
      charts.current.forEach((c) => c.destroy());
      charts.current = [];
    };
  }, []);

  const generateReport = async () => {
    if (!hasPermission('report:generate')) return;
    const report = await api.securityReport();
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `analytics-report-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const trust = (data?.trust_statistics as { total_entities?: number }) || {};
  const resp = (data?.response_summary as { active?: number }) || {};

  return (
    <>
      <div className="cds-page-hero">
        <div>
          <h2><i className="fas fa-chart-line" /> تحليلات الأداء والأمان</h2>
          <p>مؤشرات حية من API — بدون Math.random أو أرقام ثابتة</p>
        </div>
        <div className="cds-hero-actions">
          {hasPermission('report:generate') && (
            <button type="button" className="btn btn-light btn-sm" onClick={generateReport}>
              <i className="fas fa-file-alt" /> تقرير تحليلي
            </button>
          )}
        </div>
      </div>

      <div className="cds-kpi-grid mb-4">
        <div className="cds-kpi">
          <div className="cds-kpi-icon"><i className="fas fa-heartbeat" /></div>
          <div className="cds-kpi-value">{Number(data?.health_score ?? 0).toFixed(1)}</div>
          <div className="cds-kpi-label">صحة النظام</div>
          <div className="progress mt-2">
            <div className="progress-bar bg-success" style={{ width: `${Number(data?.health_score ?? 0)}%` }} />
          </div>
        </div>
        <div className="cds-kpi">
          <div className="cds-kpi-icon gold"><i className="fas fa-bolt" /></div>
          <div className="cds-kpi-value">{resp.active ?? 0}</div>
          <div className="cds-kpi-label">الاستجابات النشطة</div>
        </div>
        <div className="cds-kpi">
          <div className="cds-kpi-icon warn"><i className="fas fa-shield-check" /></div>
          <div className="cds-kpi-value">{trust.total_entities ?? 0}</div>
          <div className="cds-kpi-label">الكيانات المراقبة</div>
        </div>
        <div className="cds-kpi">
          <div className="cds-kpi-icon"><i className="fas fa-chart-line" /></div>
          <div className="cds-kpi-value">{Number(data?.efficiency ?? 0).toFixed(1)}%</div>
          <div className="cds-kpi-label">كفاءة الموارد</div>
        </div>
      </div>

      <div className="container-fluid px-0">
        <div className="row mb-4">
          <div className="col-lg-8">
            <div className="card">
              <div className="card-header"><h5 className="mb-0"><i className="fas fa-chart-area" /> Performance Trends</h5></div>
              <div className="card-body">
                <div className="chart-container" style={{ height: 350 }}>
                  <canvas ref={perfRef} />
                </div>
              </div>
            </div>
          </div>
          <div className="col-lg-4">
            <div className="card">
              <div className="card-header"><h5 className="mb-0"><i className="fas fa-chart-pie" /> Resource Distribution</h5></div>
              <div className="card-body">
                <div className="chart-container" style={{ height: 350 }}>
                  <canvas ref={resourceRef} />
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="row mb-4">
          <div className="col-lg-6">
            <div className="card">
              <div className="card-header"><h5 className="mb-0"><i className="fas fa-shield-alt" /> Security Events</h5></div>
              <div className="card-body">
                <div className="chart-container" style={{ height: 300 }}>
                  <canvas ref={eventsRef} />
                </div>
              </div>
            </div>
          </div>
          <div className="col-lg-6">
            <div className="card">
              <div className="card-header"><h5 className="mb-0"><i className="fas fa-radar" /> Threat Analysis</h5></div>
              <div className="card-body">
                <div className="chart-container" style={{ height: 300 }}>
                  <canvas ref={threatRef} />
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="row">
          <div className="col-lg-6">
            <div className="card">
              <div className="card-header"><h5 className="mb-0"><i className="fas fa-microchip" /> Top Processes</h5></div>
              <div className="card-body">
                <div className="table-responsive">
                  <table className="table table-hover">
                    <thead>
                      <tr><th>Process</th><th>PID</th><th>CPU %</th><th>Memory %</th></tr>
                    </thead>
                    <tbody>
                      {processes.map((p) => (
                        <tr key={p.pid}>
                          <td>{p.name}</td>
                          <td>{p.pid}</td>
                          <td>{p.cpu_percent.toFixed(1)}</td>
                          <td>{p.memory_percent.toFixed(1)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
