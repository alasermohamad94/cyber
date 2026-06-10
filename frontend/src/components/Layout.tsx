import { useEffect, useState } from 'react';
import { NavLink, Outlet, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { ROLE_LABELS } from '../utils/cds';

const PAGE_META: Record<string, { title: string; subtitle: string }> = {
  '/': { title: 'مركز عمليات SOC', subtitle: 'لوحة القيادة الموحدة — مستوى التهديد والحوادث' },
  '/analytics': { title: 'التحليلات', subtitle: 'أداء النظام والأمان — /api/analytics-overview (P1)' },
  '/threats': { title: 'إدارة التهديدات', subtitle: 'تهديدات وIPs محظورة — /api/threat-overview (P1)' },
  '/incidents': { title: 'إدارة الحوادث', subtitle: 'دورة حياة الحوادث والاستجابة' },
  '/entities': { title: 'مركز الثقة', subtitle: 'الكيانات، حساسية الأصول، نقاط المخاطر' },
  '/monitor': { title: 'المراقبة الفورية', subtitle: 'بث حي للأحداث والتنبيهات' },
  '/firewall': { title: 'جدار الحماية', subtitle: 'الحظر، العزل، والموافقات' },
  '/replay': { title: 'التحليل الجنائي', subtitle: 'إعادة تمثيل الأحداث' },
  '/investigation': { title: 'التحقيق', subtitle: 'مساحة عمل القضايا الأمنية' },
  '/settings': { title: 'الإعدادات', subtitle: 'تفضيلات النظام وعقد المؤشرات (Metric Contract)' },
};

export default function Layout() {
  const { session, logout } = useAuth();
  const location = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [connected, setConnected] = useState(true);
  const [dataQuality, setDataQuality] = useState<{
    freshness_seconds?: number;
    source_status?: string;
    data_mode?: string;
  } | null>(null);
  const [demoBanner, setDemoBanner] = useState<string | null>(null);

  const meta = PAGE_META[location.pathname] || PAGE_META['/'];

  useEffect(() => {
    document.body.className = `cds-app cds-auth-ready cds-role-${session?.role || 'viewer'}`;
    return () => {
      document.body.className = '';
    };
  }, [session?.role]);

  useEffect(() => {
    fetch(`${import.meta.env.VITE_API_URL || ''}/api/demo/disclaimer`)
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (d?.demo_mode) {
          setDemoBanner(d.production_path || '/api/system-metrics');
          document.body.classList.add('cds-has-demo');
        }
      })
      .catch(() => {});

    fetch(`${import.meta.env.VITE_API_URL || ''}/api/metrics-contract`, { credentials: 'include' })
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => d?.data_quality && setDataQuality(d.data_quality))
      .catch(() => {});
  }, []);

  useEffect(() => {
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const host = window.location.host;
    const ws = new WebSocket(`${proto}://${host}/ws/metrics`);
    ws.onopen = () => setConnected(true);
    ws.onclose = () => setConnected(false);
    ws.onerror = () => setConnected(false);
    return () => ws.close();
  }, []);

  const fresh = dataQuality?.freshness_seconds != null ? `${dataQuality.freshness_seconds} ث` : '—';
  const status = dataQuality?.source_status === 'ok' ? 'سليم' : 'متدهور';
  const mode = dataQuality?.data_mode === 'production' ? 'إنتاج' : dataQuality?.data_mode || '—';

  return (
    <>
      {demoBanner && (
        <div className="cds-demo-banner">
          <i className="fas fa-flask" /> وضع العرض التجريبي — المقاييس الحية من <code>{demoBanner}</code>
        </div>
      )}

      <aside className={`cds-sidebar${sidebarOpen ? ' cds-open' : ''}`} id="cds-sidebar">
        <div className="cds-sidebar-brand">
          <NavLink to="/">
            <span className="cds-logo-icon">
              <i className="fas fa-shield-alt" />
            </span>
            <span>الدفاع السيبراني</span>
          </NavLink>
        </div>
        <nav className="cds-nav">
          <NavLink to="/" end className={({ isActive }) => `cds-nav-link${isActive ? ' active' : ''}`}>
            <i className="fas fa-tachometer-alt" /> مركز SOC
          </NavLink>
          <NavLink to="/incidents" className={({ isActive }) => `cds-nav-link${isActive ? ' active' : ''}`}>
            <i className="fas fa-exclamation-circle" /> الحوادث
          </NavLink>
          <NavLink to="/entities" className={({ isActive }) => `cds-nav-link${isActive ? ' active' : ''}`}>
            <i className="fas fa-fingerprint" /> الثقة
          </NavLink>
          <NavLink to="/monitor" className={({ isActive }) => `cds-nav-link${isActive ? ' active' : ''}`}>
            <i className="fas fa-broadcast-tower" /> المراقبة
          </NavLink>
          <NavLink to="/firewall" className={({ isActive }) => `cds-nav-link${isActive ? ' active' : ''}`}>
            <i className="fas fa-fire" /> الجدار
          </NavLink>
          <NavLink to="/investigation" className={({ isActive }) => `cds-nav-link${isActive ? ' active' : ''}`}>
            <i className="fas fa-search" /> التحقيق
          </NavLink>
          <NavLink to="/analytics" className={({ isActive }) => `cds-nav-link${isActive ? ' active' : ''}`}>
            <i className="fas fa-chart-line" /> التحليلات
          </NavLink>
          <NavLink to="/threats" className={({ isActive }) => `cds-nav-link${isActive ? ' active' : ''}`}>
            <i className="fas fa-shield-virus" /> التهديدات
          </NavLink>
          <NavLink to="/settings" className={({ isActive }) => `cds-nav-link${isActive ? ' active' : ''}`}>
            <i className="fas fa-cog" /> الإعدادات
          </NavLink>
        </nav>
        <div className="cds-sidebar-footer">
          <button type="button" className="cds-logout border-0 bg-transparent w-100" onClick={() => logout()}>
            <i className="fas fa-sign-out-alt" /> تسجيل الخروج
          </button>
        </div>
      </aside>

      <button
        type="button"
        className="cds-sidebar-toggle"
        aria-label="القائمة"
        onClick={() => setSidebarOpen((v) => !v)}
      >
        <i className="fas fa-bars" />
      </button>

      <div className="cds-main">
        <header className="cds-topbar">
          <div>
            <h1 className="cds-topbar-title">
              {meta.title}
              <small>{meta.subtitle}</small>
            </h1>
          </div>
          <div className="cds-topbar-meta">
            <div
              className={`cds-data-quality${dataQuality?.source_status !== 'ok' ? ' cds-dq-degraded' : ''}`}
              id="cds-data-quality"
            >
              <span className="cds-dq-item">
                <i className="fas fa-database" /> المصدر: <strong>{status}</strong>
              </span>
              <span className="cds-dq-item">
                <i className="fas fa-clock" /> حداثة البيانات: <strong>{fresh}</strong>
              </span>
              <span className="cds-dq-item">
                <i className="fas fa-layer-group" /> الوضع: <strong>{mode}</strong>
              </span>
            </div>
            <div className="cds-user-chip">
              <i className="fas fa-user-circle" />
              <span id="cds-username">{session?.username || '—'}</span>
              <span id="cds-role-badge" className={`cds-role-badge cds-role-${session?.role}`}>
                {ROLE_LABELS[session?.role || ''] || session?.role}
              </span>
            </div>
          </div>
        </header>

        <main className="cds-content cds-fade-in">
          <Outlet />
        </main>
      </div>

      <div className={`cds-connection-pill ${connected ? 'connected' : 'disconnected'}`} id="connection-indicator">
        <i className={`fas fa-wifi${connected ? '' : '-slash'}`} /> {connected ? 'متصل' : 'غير متصل'}
      </div>
    </>
  );
}
