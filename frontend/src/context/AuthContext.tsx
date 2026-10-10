/**
 * Authentication context — SPA PKCE / Bearer-only architecture.
 * Access tokens are kept in React state (memory only), never localStorage.
 * Session storage is used ONLY for the temporary PKCE verifier/state during
 * the OAuth redirect (not applicable in demo mode).
 */
import React, { createContext, useCallback, useContext, useState } from 'react';
import type { AuthState, UserRole } from '../types';

interface AuthContextValue extends AuthState {
  setAuth: (state: AuthState) => void;
  logout: () => void;
  hasRole: (required: UserRole) => boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

const ROLE_HIERARCHY: Record<UserRole, UserRole[]> = {
  viewer: ['viewer', 'operator', 'admin'],
  operator: ['operator', 'admin'],
  admin: ['admin'],
};

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [auth, setAuthState] = useState<AuthState>({
    token: null,
    role: null,
    username: null,
    isAuthenticated: false,
  });

  const setAuth = useCallback((newAuth: AuthState) => {
    setAuthState(newAuth);
  }, []);

  const logout = useCallback(() => {
    // Clear in-memory token — no localStorage to clear
    setAuthState({
      token: null,
      role: null,
      username: null,
      isAuthenticated: false,
    });
    // Clear any temporary PKCE verifier stored in sessionStorage
    sessionStorage.removeItem('pkce_verifier');
    sessionStorage.removeItem('pkce_state');
  }, []);

  const hasRole = useCallback(
    (required: UserRole) => {
      if (!auth.role) return false;
      const allowed = ROLE_HIERARCHY[required] ?? [required];
      return allowed.includes(auth.role);
    },
    [auth.role]
  );

  return (
    <AuthContext.Provider value={{ ...auth, setAuth, logout, hasRole }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
