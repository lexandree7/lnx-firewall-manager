import React, { useState, useEffect } from 'react';
import { Shield, Lock, User, KeyRound, ArrowRight, Globe, AlertCircle, Sparkles } from 'lucide-react';
import { api } from '../api/client';
import { User as UserType } from '../types';

interface LoginProps {
  onLoginSuccess: (user: UserType) => void;
  lang: 'pt' | 'en';
  onToggleLang: () => void;
  errorMessage?: string;
}

export const Login: React.FC<LoginProps> = ({
  onLoginSuccess,
  lang,
  onToggleLang,
  errorMessage: initialError,
}) => {
  const [username, setUsername] = useState('root');
  const [password, setPassword] = useState('');
  const [totpCode, setTotpCode] = useState('');
  const [showTotpField, setShowTotpField] = useState(false);
  const [error, setError] = useState<string | null>(initialError || null);
  const [loading, setLoading] = useState(false);
  const [oidcStatus, setOidcStatus] = useState<{ enabled: boolean; provider_name: string }>({
    enabled: false,
    provider_name: 'OpenID Connect',
  });

  useEffect(() => {
    api.getOIDCStatus().then((status) => {
      setOidcStatus(status);
    }).catch(() => {});
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const res = await api.login(username.trim(), password, showTotpField ? totpCode.trim() : undefined);
      if (res.success && res.user) {
        onLoginSuccess(res.user);
      } else {
        const errMsg = res.error || (lang === 'pt' ? 'Falha na autenticação' : 'Authentication failed');
        if (errMsg.toLowerCase().includes('totp') || errMsg.toLowerCase().includes('2fa') || errMsg.toLowerCase().includes('código')) {
          setShowTotpField(true);
        }
        setError(errMsg);
      }
    } catch (err: any) {
      setError(err.message || 'Erro de conexão');
    } finally {
      setLoading(false);
    }
  };

  const handleOIDCLogin = () => {
    window.location.href = '/api/v1/auth/oidc/login';
  };

  return (
    <div className="min-h-screen bg-black text-zinc-100 flex flex-col justify-center items-center px-4 relative overflow-hidden selection:bg-amber-500/30 selection:text-amber-200">
      {/* Background ambient accents */}
      <div className="absolute -top-40 -left-40 w-96 h-96 bg-amber-600/10 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute -bottom-40 -right-40 w-96 h-96 bg-amber-500/5 rounded-full blur-3xl pointer-events-none" />

      {/* Top bar with Language Switcher */}
      <div className="absolute top-6 right-6">
        <button
          onClick={onToggleLang}
          className="flex items-center gap-1.5 text-xs font-mono font-medium text-zinc-400 hover:text-white px-3 py-1.5 rounded-lg border border-zinc-800 bg-zinc-950/80 backdrop-blur transition hover:border-zinc-700"
        >
          <Globe className="w-3.5 h-3.5 text-amber-500" />
          <span>{lang.toUpperCase()}</span>
        </button>
      </div>

      {/* Login Card */}
      <div className="w-full max-w-md bg-zinc-950/90 border border-zinc-800 rounded-2xl shadow-2xl shadow-black p-8 relative z-10 backdrop-blur">
        {/* Brand Header */}
        <div className="flex flex-col items-center text-center mb-8">
          <div className="w-14 h-14 rounded-2xl bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400 mb-4 shadow-lg shadow-amber-500/10">
            <Shield className="w-8 h-8" />
          </div>
          <h1 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
            <span>Linux Firewall Manager</span>
            <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">
              v1.0
            </span>
          </h1>
          <p className="text-xs text-zinc-400 font-mono mt-1">
            {lang === 'pt' ? 'Painel de Controle Central de Netfilter' : 'Central Netfilter Control Plane'}
          </p>
        </div>

        {/* Error Alert */}
        {error && (
          <div className="mb-6 p-3 rounded-lg bg-red-950/40 border border-red-800/60 text-red-300 text-xs flex items-start gap-2 animate-shake">
            <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
            <div className="flex-1">{error}</div>
          </div>
        )}

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-zinc-300 mb-1.5 font-mono">
              {lang === 'pt' ? 'Usuário' : 'Username'}
            </label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-zinc-500">
                <User className="w-4 h-4" />
              </div>
              <input
                type="text"
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder={lang === 'pt' ? 'Nome de usuário (ex: root)' : 'Username (e.g. root)'}
                className="w-full bg-black/60 border border-zinc-800 rounded-lg pl-9 pr-3 py-2 text-sm text-zinc-100 placeholder-zinc-600 focus:outline-none focus:border-amber-500 transition font-mono"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-zinc-300 mb-1.5 font-mono">
              {lang === 'pt' ? 'Senha' : 'Password'}
            </label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-zinc-500">
                <Lock className="w-4 h-4" />
              </div>
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full bg-black/60 border border-zinc-800 rounded-lg pl-9 pr-3 py-2 text-sm text-zinc-100 placeholder-zinc-600 focus:outline-none focus:border-amber-500 transition font-mono"
              />
            </div>
          </div>

          {/* 2FA TOTP field */}
          {showTotpField ? (
            <div className="animate-fadeIn">
              <label className="block text-xs font-medium text-amber-300 mb-1.5 font-mono flex items-center justify-between">
                <span>{lang === 'pt' ? 'Código 2FA / TOTP (6 dígitos)' : '2FA / TOTP Code (6 digits)'}</span>
                <button
                  type="button"
                  onClick={() => { setShowTotpField(false); setTotpCode(''); }}
                  className="text-[10px] text-zinc-500 hover:text-zinc-400 underline"
                >
                  {lang === 'pt' ? 'Ocultar' : 'Hide'}
                </button>
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-amber-500">
                  <KeyRound className="w-4 h-4" />
                </div>
                <input
                  type="text"
                  maxLength={6}
                  autoFocus
                  value={totpCode}
                  onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ''))}
                  placeholder="123456"
                  className="w-full bg-black/60 border border-amber-500/50 rounded-lg pl-9 pr-3 py-2 text-sm text-amber-200 placeholder-zinc-600 focus:outline-none focus:border-amber-400 transition font-mono tracking-widest text-center"
                />
              </div>
            </div>
          ) : (
            <div className="text-right">
              <button
                type="button"
                onClick={() => setShowTotpField(true)}
                className="text-xs text-zinc-500 hover:text-amber-400 transition font-mono"
              >
                + {lang === 'pt' ? 'Possui autenticação 2FA?' : 'Using 2FA / TOTP?'}
              </button>
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full mt-2 bg-amber-600 hover:bg-amber-500 text-black font-bold py-2.5 px-4 rounded-lg flex items-center justify-center gap-2 transition disabled:opacity-50 shadow-md shadow-amber-600/20 active:scale-[0.99]"
          >
            {loading ? (
              <span className="inline-block w-4 h-4 border-2 border-black border-t-transparent rounded-full animate-spin" />
            ) : (
              <>
                <span>{lang === 'pt' ? 'Acessar Painel' : 'Sign In'}</span>
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>
        </form>

        {/* OIDC / Federated SSO Section */}
        {oidcStatus.enabled && (
          <div className="mt-6 pt-6 border-t border-zinc-800/80">
            <div className="relative flex py-1 items-center mb-4">
              <div className="flex-grow border-t border-zinc-800"></div>
              <span className="flex-shrink mx-3 text-[11px] text-zinc-500 font-mono uppercase">
                {lang === 'pt' ? 'ou login corporativo' : 'or enterprise SSO'}
              </span>
              <div className="flex-grow border-t border-zinc-800"></div>
            </div>

            <button
              type="button"
              onClick={handleOIDCLogin}
              className="w-full bg-zinc-900 hover:bg-zinc-800 text-zinc-200 hover:text-white border border-zinc-700 hover:border-amber-500/50 py-2.5 px-4 rounded-lg flex items-center justify-center gap-2.5 transition text-sm font-medium group cursor-pointer"
            >
              <Sparkles className="w-4 h-4 text-amber-400 group-hover:rotate-12 transition-transform" />
              <span>
                {lang === 'pt'
                  ? `Entrar com ${oidcStatus.provider_name}`
                  : `Sign in with ${oidcStatus.provider_name}`}
              </span>
            </button>
          </div>
        )}
      </div>

      {/* Footer info */}
      <div className="mt-8 text-center text-xs text-zinc-600 font-mono">
        Linux Firewall Manager • Zero-Shell Architecture • Argon2id & OpenID Connect
      </div>
    </div>
  );
};
