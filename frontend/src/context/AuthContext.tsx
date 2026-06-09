import React, { createContext, useCallback, useContext, useEffect, useState } from 'react';
import { api, SessionInfo } from '../api/client';

interface AuthState {
  session: SessionInfo | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<string | null>;
  logout: () => Promise<void>;
  hasPermission: (perm: string) => boolean;
  refresh: () => Promise<void>;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [session, setSession] = useState<SessionInfo | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    try {
      const info = await api.sessionInfo();
      setSession(info);
    } catch {
      setSession(null);
    }
  }, []);

  useEffect(() => {
    refresh().finally(() => setLoading(false));
  }, [refresh]);

  const login = async (username: string, password: string) => {
    const result = await api.login(username, password);
    if (!result.success) {
      return result.error || 'فشل تسجيل الدخول';
    }
    await refresh();
    return null;
  };

  const logout = async () => {
    await api.logout();
    setSession(null);
  };

  const hasPermission = (perm: string) =>
    Boolean(session?.permissions?.includes(perm));

  return (
    <AuthContext.Provider value={{ session, loading, login, logout, hasPermission, refresh }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
