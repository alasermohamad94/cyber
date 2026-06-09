export const CDS_COLORS = {
  primary: '#002623',
  secondary: '#054239',
  gold: '#b9a779',
  medium: '#988561',
  severity: {
    low: '#054239',
    medium: '#b9a779',
    high: '#6b1f2a',
    critical: '#4a151e',
  },
  chart: ['#002623', '#054239', '#b9a779', '#988561', '#6b1f2a', '#4a151e', '#3d3a3b', '#161616'],
};

export const ROLE_LABELS: Record<string, string> = {
  admin: 'مدير النظام',
  analyst: 'محلل',
  viewer: 'مشاهدة',
};

export function severityBadgeClass(severity: string): string {
  const map: Record<string, string> = {
    low: 'info',
    medium: 'warning',
    high: 'danger',
    critical: 'dark',
  };
  return map[severity] || 'secondary';
}

export function initChartDefaults() {
  if (typeof Chart === 'undefined') return;
  Chart.defaults.color = '#161616';
  Chart.defaults.borderColor = 'rgba(0, 38, 35, 0.12)';
  Chart.defaults.font.family = "'Tajawal', 'Segoe UI', sans-serif";
}
