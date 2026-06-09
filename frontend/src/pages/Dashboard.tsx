import { useCallback, useEffect, useRef, useState } from 'react';
import { api } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { CDS_COLORS, initChartDefaults, severityBadgeClass } from '../utils/cds';

type SecurityEvent = {
  description: string;
  severity: string;
  time_formatted: string;
  event_type: string;
};

export default function Dashboard() {
  const { hasPermission } = useAuth();
  const perfRef = useRef<HTMLCanvasElement>(null);
  const riskRef = useRef<HTMLCanvasElement>(null);
  const perfChart = useRef<ChartInstance | null>(null);
  const riskChart = useRef<ChartInstance | null>(null);

  const [metrics, setMetrics] = useState({
    cpu: 0,
    memory: 0,
    disk: 0,
    connections: 0,
    uptime: '0ث',
  });
  const [security, setSecurity] = useState({
    total_entities: 0,
    active_responses: 0,
    total_events: 0,
    active_alerts: 0,
    risk_distribution: { low: 0, medium: 0, high: 0, critical: 0 },
    recent_events: [] as SecurityEvent[],
  });

  const load = useCallback(async () => {
    const [m, s] = await Promise.all([api.systemMetrics(), api.securityOverview()]);
    setMetrics({
      cpu: Number(m.cpu_percent) || 0,
      memory: Number(m.memory_percent) || 0,
      disk: Number(m.disk_usage) || 0,
      connections: Number(m.active_connections) || 0,
      uptime: String(m.uptime_formatted || '0ث'),
    });
    const trust = (s.trust_statistics as Record<string, unknown>) || {};
    setSecurity({
      total_entities: Number(trust.total_entities) || 0,
      active_responses: Array.isArray(s.active_responses) ? s.active_responses.length : 0,
      total_events: Number(s.total_events) || 0,
      active_alerts: Number(s.active_alerts) || 0,
      risk_distribution: (trust.risk_distribution as typeof security.risk_distribution) || security.risk_distribution,
      recent_events: (s.recent_events as SecurityEvent[]) || [],
    });

    if (perfChart.current && m.cpu_percent != null) {
      const now = new Date().toLocaleTimeString();
      const chart = perfChart.current;
      chart.data.labels.push(now);
      chart.data.datasets[0].data.push(Number(m.cpu_percent));
      chart.data.datasets[1].data.push(Number(m.memory_percent));
      if (chart.data.labels.length > 20) {
        chart.data.labels.shift();
        chart.data.datasets[0].data.shift();
        chart.data.datasets[1].data.shift();
      }
      chart.update('none');
    }

    if (riskChart.current && trust.risk_distribution) {
      const rd = trust.risk_distribution as Record<string, number>;
      riskChart.current.data.datasets[0].data = [
        rd.low || 0,
        rd.medium || 0,
        rd.high || 0,
        rd.critical || 0,
      ];
      riskChart.current.update();
    }
  }, []);

  useEffect(() => {
    initChartDefaults();
    if (perfRef.current && typeof Chart !== 'undefined') {
      perfChart.current = new Chart(perfRef.current.getContext('2d')!, {
        type: 'line',
        data: {
          labels: [],
          datasets: [
            {
              label: 'المعالج %',
              data: [],
              borderColor: CDS_COLORS.primary,
              backgroundColor: 'rgba(0, 38, 35, 0.12)',
              tension: 0.4,
            },
            {
              label: 'الذاكرة %',
              data: [],
              borderColor: CDS_COLORS.gold,
              backgroundColor: 'rgba(185, 167, 121, 0.2)',
              tension: 0.4,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: { y: { beginAtZero: true, max: 100 } },
        },
      });
    }
    if (riskRef.current && typeof Chart !== 'undefined') {
      riskChart.current = new Chart(riskRef.current.getContext('2d')!, {
        type: 'doughnut',
        data: {
          labels: ['منخفض', 'متوسط', 'مرتفع', 'حرج'],
          datasets: [{
            data: [0, 0, 0, 0],
            backgroundColor: [
              CDS_COLORS.severity.low,
              CDS_COLORS.severity.medium,
              CDS_COLORS.severity.high,
              CDS_COLORS.severity.critical,
            ],
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { position: 'bottom' } },
        },
      });
    }
    load();
    const id = setInterval(load, 5000);
    return () => {
      clearInterval(id);
      perfChart.current?.destroy();
      riskChart.current?.destroy();
    };
  }, [load]);

  const generateReport = async () => {
    if (!hasPermission('report:generate')) return;
    const report = await api.securityReport();
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `security-report-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <>
      <div className="cds-page-hero">
        <div>
          <h2><i className="fas fa-tachometer-alt" /> نظرة عامة تشغيلية</h2>
          <p>جميع المؤشرات من واجهات API الموحّدة — لا بيانات وهمية</p>
        </div>
        <div className="cds-hero-actions">
          {hasPermission('report:generate') && (
            <button type="button" className="btn btn-light btn-sm" onClick={generateReport}>
              <i className="fas fa-file-alt" /> تقرير أمني
            </button>
          )}
          <button type="button" className="btn btn-warning btn-sm" onClick={load}>
            <i className="fas fa-sync-alt" /> تحديث
          </button>
        </div>
      </div>

      <div className="cds-kpi-grid">
        <div className="cds-kpi">
          <div className="cds-kpi-icon"><i className="fas fa-microchip" /></div>
          <div className="cds-kpi-value">{metrics.cpu.toFixed(1)}%</div>
          <div className="cds-kpi-label">استخدام المعالج</div>
          <div className="progress mt-2">
            <div className="progress-bar bg-primary" style={{ width: `${metrics.cpu}%` }} />
          </div>
        </div>
        <div className="cds-kpi">
          <div className="cds-kpi-icon gold"><i className="fas fa-memory" /></div>
          <div className="cds-kpi-value">{metrics.memory.toFixed(1)}%</div>
          <div className="cds-kpi-label">الذاكرة</div>
          <div className="progress mt-2">
            <div className="progress-bar bg-success" style={{ width: `${metrics.memory}%` }} />
          </div>
        </div>
        <div className="cds-kpi">
          <div className="cds-kpi-icon warn"><i className="fas fa-hdd" /></div>
          <div className="cds-kpi-value">{metrics.disk.toFixed(1)}%</div>
          <div className="cds-kpi-label">القرص</div>
          <div className="progress mt-2">
            <div className="progress-bar bg-warning" style={{ width: `${metrics.disk}%` }} />
          </div>
        </div>
        <div className="cds-kpi">
          <div className="cds-kpi-icon"><i className="fas fa-network-wired" /></div>
          <div className="cds-kpi-value">{metrics.connections}</div>
          <div className="cds-kpi-label">الاتصالات النشطة</div>
          <small className="text-muted">وقت التشغيل: {metrics.uptime}</small>
        </div>
      </div>

      <div className="row fade-in">
        <div className="col-lg-8 mb-4">
          <div className="card">
            <div className="card-header"><i className="fas fa-chart-line" /> الأداء اللحظي</div>
            <div className="card-body">
              <div className="chart-container" style={{ height: 300 }}>
                <canvas ref={perfRef} />
              </div>
            </div>
          </div>
        </div>
        <div className="col-lg-4 mb-4">
          <div className="card">
            <div className="card-header"><i className="fas fa-shield-alt" /> ملخص الأمان</div>
            <div className="card-body">
              <div className="row text-center mb-3">
                <div className="col-6">
                  <h5 className="text-primary">{security.total_entities}</h5>
                  <small className="text-muted">الكيانات</small>
                </div>
                <div className="col-6">
                  <h5 className="text-warning">{security.active_responses}</h5>
                  <small className="text-muted">استجابات نشطة</small>
                </div>
              </div>
              <div className="row text-center mb-3">
                <div className="col-6">
                  <h5 className="text-info">{security.total_events}</h5>
                  <small className="text-muted">إجمالي الأحداث</small>
                </div>
                <div className="col-6">
                  <h5 className="text-danger">{security.active_alerts}</h5>
                  <small className="text-muted">تنبيهات نشطة</small>
                </div>
              </div>
              <div className="chart-container" style={{ height: 200 }}>
                <canvas ref={riskRef} />
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="row fade-in">
        <div className="col-lg-6 mb-4">
          <div className="card">
            <div className="card-header"><i className="fas fa-exclamation-triangle" /> أحداث أمنية حديثة</div>
            <div className="card-body" style={{ maxHeight: 400, overflowY: 'auto' }}>
              {security.recent_events.length === 0 ? (
                <div className="text-center text-muted">
                  <i className="fas fa-check-circle fa-3x mb-3" />
                  <p>لا توجد أحداث أمنية حديثة</p>
                </div>
              ) : (
                security.recent_events.map((e, i) => (
                  <div key={i} className={`security-event ${e.severity} p-2 mb-2 border-start border-4`}>
                    <div className="d-flex justify-content-between">
                      <span>{e.description}</span>
                      <span className={`badge bg-${severityBadgeClass(e.severity)}`}>{e.severity}</span>
                    </div>
                    <small className="text-muted">{e.time_formatted}</small>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
        <div className="col-lg-6 mb-4">
          <div className="card">
            <div className="card-header"><i className="fas fa-bolt" /> إجراءات سريعة</div>
            <div className="card-body">
              <div className="row g-3">
                {hasPermission('report:generate') && (
                  <div className="col-md-6">
                    <button type="button" className="btn btn-info w-100" onClick={generateReport}>
                      <i className="fas fa-file-alt" /> تقرير أمني
                    </button>
                  </div>
                )}
                <div className="col-md-6">
                  <button type="button" className="btn btn-success w-100" onClick={load}>
                    <i className="fas fa-sync-alt" /> تحديث البيانات
                  </button>
                </div>
              </div>
              <hr />
              <h6>حالة النظام</h6>
              <div className="d-flex justify-content-between align-items-center mb-2">
                <span>جدار الحماية</span><span className="badge bg-success">نشط</span>
              </div>
              <div className="d-flex justify-content-between align-items-center mb-2">
                <span>النسخ الاحتياطي</span><span className="badge bg-info">مجدول</span>
              </div>
              <div className="d-flex justify-content-between align-items-center mb-2">
                <span>الصيانة</span><span className="badge bg-secondary">متوقف</span>
              </div>
              <div className="d-flex justify-content-between align-items-center">
                <span>مستوى الأمان</span><span className="badge bg-warning">مرتفع</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
