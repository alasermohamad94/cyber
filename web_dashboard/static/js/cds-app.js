/**
 * Cyber Defense System — RBAC UI (admin / analyst / viewer)
 */
(function (global) {
    const CDS = {
        colors: {
            primary: '#002623',
            secondary: '#054239',
            gold: '#b9a779',
            medium: '#988561',
            umber: '#6b1f2a',
            accent: '#4a151e',
            chart: ['#002623', '#054239', '#b9a779', '#988561', '#6b1f2a', '#4a151e', '#3d3a3b', '#161616'],
            severity: {
                low: '#054239',
                medium: '#b9a779',
                high: '#6b1f2a',
                critical: '#4a151e',
            },
        },
        session: null,
        dataQuality: null,
    };

    const ROLE_LABELS = {
        admin: 'مدير النظام',
        analyst: 'محلل',
        viewer: 'مشاهدة',
    };

    function hasPermission(perm) {
        if (!perm) return false;
        if (!CDS.session || !Array.isArray(CDS.session.permissions)) {
            return false;
        }
        return CDS.session.permissions.includes(perm);
    }

    function denyAction(perm) {
        const msg = 'ليس لديك صلاحية: ' + perm;
        if (typeof showNotification === 'function') {
            showNotification(msg, 'warning');
        } else {
            console.warn(msg);
        }
        return false;
    }

    function requirePermission(perm) {
        if (hasPermission(perm)) return true;
        return denyAction(perm);
    }

    function applyPermissionUI() {
        document.querySelectorAll('[data-permission]').forEach((el) => {
            const perm = el.getAttribute('data-permission');
            const allowed = hasPermission(perm);
            if (!allowed) {
                el.classList.add('cds-hidden-perm');
                el.setAttribute('aria-hidden', 'true');
                if (el.tagName === 'BUTTON' || el.tagName === 'A') {
                    el.disabled = true;
                }
            } else {
                el.classList.remove('cds-hidden-perm');
                el.removeAttribute('aria-hidden');
                if (el.tagName === 'BUTTON') {
                    el.disabled = false;
                }
            }
        });
    }

    function markAuthReady() {
        document.body.classList.add('cds-auth-ready');
    }

    function renderSessionBar() {
        const userEl = document.getElementById('cds-username');
        const roleEl = document.getElementById('cds-role-badge');
        if (!CDS.session) return;
        if (userEl) userEl.textContent = CDS.session.username || '—';
        if (roleEl) {
            const role = CDS.session.role || 'viewer';
            roleEl.textContent = ROLE_LABELS[role] || role;
            roleEl.className = 'cds-role-badge cds-role-' + role;
        }
        document.body.classList.remove('cds-role-admin', 'cds-role-analyst', 'cds-role-viewer');
        if (CDS.session.role) {
            document.body.classList.add('cds-role-' + CDS.session.role);
        }
    }

    function renderDataQualityBar(dq) {
        const bar = document.getElementById('cds-data-quality');
        if (!bar || !dq) return;
        const fresh = dq.freshness_seconds != null ? dq.freshness_seconds + ' ث' : '—';
        const status = dq.source_status === 'ok' ? 'سليم' : 'متدهور';
        const mode = dq.data_mode === 'production' ? 'إنتاج' : dq.data_mode;
        bar.innerHTML = `
            <span class="cds-dq-item"><i class="fas fa-database"></i> المصدر: <strong>${status}</strong></span>
            <span class="cds-dq-item"><i class="fas fa-clock"></i> حداثة البيانات: <strong>${fresh}</strong></span>
            <span class="cds-dq-item"><i class="fas fa-layer-group"></i> الوضع: <strong>${mode}</strong></span>
        `;
        bar.classList.toggle('cds-dq-degraded', dq.source_status !== 'ok');
    }

    function renderDemoBanner(demo) {
        const banner = document.getElementById('cds-demo-banner');
        if (!banner) return;
        if (demo && demo.demo_mode) {
            banner.hidden = false;
            banner.innerHTML = `
                <i class="fas fa-flask"></i>
                <span>وضع العرض التجريبي — المقاييس الحية من <code>${demo.production_path || '/api/system-metrics'}</code></span>
            `;
        } else {
            banner.hidden = true;
        }
    }

    async function loadSessionInfo() {
        try {
            const res = await fetch('/api/session-info', { credentials: 'same-origin' });
            if (res.status === 401) {
                window.location.href = '/login';
                return;
            }
            if (!res.ok) return;
            CDS.session = await res.json();
            global.CDS = CDS;
            renderSessionBar();
            applyPermissionUI();
            markAuthReady();
        } catch (e) {
            console.warn('session-info', e);
        }
    }

    async function loadDataQuality() {
        try {
            const res = await fetch('/api/metrics-contract', { credentials: 'same-origin' });
            if (!res.ok) return;
            const data = await res.json();
            CDS.dataQuality = data.data_quality;
            renderDataQualityBar(data.data_quality);
        } catch (e) {
            console.warn('metrics-contract', e);
        }
    }

    async function loadDemoDisclaimer() {
        try {
            const res = await fetch('/api/demo/disclaimer');
            if (!res.ok) return;
            renderDemoBanner(await res.json());
        } catch (e) {
            console.warn('demo disclaimer', e);
        }
    }

    function getSeverityColor(severity) {
        return CDS.colors.severity[severity] || CDS.colors.medium;
    }

    function getSeverityBadgeClass(severity) {
        const map = { low: 'info', medium: 'warning', high: 'danger', critical: 'dark' };
        return map[severity] || 'secondary';
    }

    function initForestCharts() {
        if (typeof Chart === 'undefined') return;
        Chart.defaults.color = '#161616';
        Chart.defaults.borderColor = 'rgba(0, 38, 35, 0.12)';
        Chart.defaults.font.family = "'Tajawal', 'Segoe UI', sans-serif";
    }

    async function initDashboardChrome() {
        initForestCharts();
        await loadSessionInfo();
        await Promise.all([loadDemoDisclaimer(), loadDataQuality()]);
        applyPermissionUI();
    }

    CDS.hasPermission = hasPermission;
    CDS.requirePermission = requirePermission;
    CDS.applyPermissionUI = applyPermissionUI;
    CDS.getSeverityColor = getSeverityColor;
    CDS.getSeverityBadgeClass = getSeverityBadgeClass;
    CDS.initDashboardChrome = initDashboardChrome;
    CDS.renderDataQualityBar = renderDataQualityBar;

    global.CDS = CDS;

    document.addEventListener('DOMContentLoaded', function () {
        if (document.body.classList.contains('cds-app')) {
            initDashboardChrome();
        }
    });
})(typeof window !== 'undefined' ? window : global);
