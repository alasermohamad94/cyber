import { FormEvent, useEffect, useState } from 'react';
import { Navigate } from 'react-router-dom';
import { api } from '../api/client';
import { useAuth } from '../context/AuthContext';

export default function Login() {
  const { session, login, loading } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [hints, setHints] = useState<{ username: string; role_label: string; password_hint: string }[]>([]);
  const [envFile, setEnvFile] = useState<string | null>(null);

  useEffect(() => {
    document.body.className = 'cds-login';
    api.loginHints().then((r) => {
      setHints(r.accounts);
      setEnvFile((r as { env_file?: string }).env_file || null);
    }).catch(() => {});
    return () => {
      document.body.className = '';
    };
  }, []);

  if (!loading && session) return <Navigate to="/" replace />;

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError('');
    const err = await login(username, password);
    if (err) setError(err);
  };

  return (
    <div className="cds-login-panel">
      <div className="cds-login-header">
        <div className="cds-login-logo">
          <i className="fas fa-shield-alt" />
        </div>
        <h1>نظام الدفاع السيبراني</h1>
        <p>منصة مراقبة واستجابة أمنية</p>
      </div>
      <div className="cds-login-body">
        {error && <div className="alert alert-danger mb-3">{error}</div>}
        {envFile && (
          <div className="alert alert-info small py-2 mb-3">
            <i className="fas fa-file-alt" /> تم تحميل الإعدادات من: <code>{envFile}</code>
          </div>
        )}
        <form onSubmit={onSubmit}>
          <div className="mb-3">
            <label className="form-label">اسم المستخدم</label>
            <input
              type="text"
              className="form-control"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              autoFocus
              placeholder={hints[0]?.username || 'admin'}
            />
          </div>
          <div className="mb-3">
            <label className="form-label">كلمة المرور</label>
            <input
              type="password"
              className="form-control"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              autoComplete="current-password"
            />
          </div>
          <button type="submit" className="btn btn-primary w-100 py-2">
            <i className="fas fa-sign-in-alt" /> دخول
          </button>
        </form>
        {hints.length > 0 && (
          <div className="cds-login-hint">
            <strong>بيانات الدخول الفعلية على هذا الجهاز:</strong>
            <table className="table table-sm mt-2 mb-0">
              <thead>
                <tr>
                  <th>المستخدم</th>
                  <th>كلمة المرور</th>
                  <th>الصلاحية</th>
                </tr>
              </thead>
              <tbody>
                {hints.map((h) => (
                  <tr key={h.username}>
                    <td><code>{h.username}</code></td>
                    <td><code>{h.password_hint}</code></td>
                    <td>{h.role_label}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
