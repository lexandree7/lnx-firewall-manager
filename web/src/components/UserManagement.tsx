import React, { useState, useEffect } from 'react';
import {
  User as UserIcon,
  Shield,
  Key,
  Smartphone,
  CheckCircle2,
  AlertTriangle,
  Lock,
  Copy,
  Check,
  RefreshCw,
  LogOut,
  Laptop,
  Globe,
  Settings,
  X,
  Eye,
  EyeOff,
  Server
} from 'lucide-react';
import QRCode from 'qrcode';
import { api } from '../api/client';
import { User, UserSession, OIDCConfig, TOTPSetupData } from '../types';

interface UserManagementProps {
  currentUser: User;
  onUpdateUser: (user: User) => void;
  lang: 'pt' | 'en';
  onClose: () => void;
}

type TabType = 'profile' | '2fa' | 'sessions' | 'oidc';

export const UserManagement: React.FC<UserManagementProps> = ({
  currentUser,
  onUpdateUser,
  lang,
  onClose,
}) => {
  const [activeTab, setActiveTab] = useState<TabType>('profile');

  // Profile / Password State
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [passwordMsg, setPasswordMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [savingPassword, setSavingPassword] = useState(false);

  // 2FA TOTP State
  const [totpSetup, setTotpSetup] = useState<TOTPSetupData | null>(null);
  const [qrCodeDataUrl, setQrCodeDataUrl] = useState<string | null>(null);
  const [totpCode, setTotpCode] = useState('');
  const [totpDisablePassword, setTotpDisablePassword] = useState('');
  const [totpMsg, setTotpMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [totpLoading, setTotpLoading] = useState(false);
  const [copiedSecret, setCopiedSecret] = useState(false);

  // Sessions State
  const [sessions, setSessions] = useState<UserSession[]>([]);
  const [sessionsLoading, setSessionsLoading] = useState(false);

  // OIDC State (Admin only)
  const [oidcConfig, setOidcConfig] = useState<OIDCConfig>({
    enabled: false,
    provider_name: 'OpenID Connect',
    issuer_url: '',
    client_id: '',
    client_secret: '',
    redirect_url: window.location.origin + '/api/v1/auth/oidc/callback',
    scopes: 'openid profile email',
    default_role: 'viewer',
  });
  const [showClientSecret, setShowClientSecret] = useState(false);
  const [oidcMsg, setOidcMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [oidcLoading, setOidcLoading] = useState(false);
  const [oidcTestResult, setOidcTestResult] = useState<any | null>(null);
  const [testingOIDC, setTestingOIDC] = useState(false);

  // Load initial tab data
  useEffect(() => {
    if (activeTab === 'sessions') {
      loadSessions();
    } else if (activeTab === 'oidc' && currentUser.role === 'admin') {
      loadOIDCConfig();
    }
  }, [activeTab]);

  const loadSessions = async () => {
    setSessionsLoading(true);
    try {
      const data = await api.listSessions();
      setSessions(data);
    } catch (e: any) {
      console.error('Falha ao buscar sessões:', e);
    } finally {
      setSessionsLoading(false);
    }
  };

  const loadOIDCConfig = async () => {
    setOidcLoading(true);
    try {
      const cfg = await api.getOIDCSettings();
      setOidcConfig(cfg);
    } catch (e: any) {
      console.error('Falha ao carregar OIDC:', e);
    } finally {
      setOidcLoading(false);
    }
  };

  const handlePasswordChange = async (e: React.FormEvent) => {
    e.preventDefault();
    setPasswordMsg(null);

    if (newPassword.length < 8) {
      setPasswordMsg({
        type: 'error',
        text: lang === 'pt' ? 'A nova senha deve possuir pelo menos 8 caracteres.' : 'New password must have at least 8 characters.',
      });
      return;
    }

    if (newPassword !== confirmPassword) {
      setPasswordMsg({
        type: 'error',
        text: lang === 'pt' ? 'A confirmação de senha não coincide.' : 'Passwords do not match.',
      });
      return;
    }

    setSavingPassword(true);
    try {
      const res = await api.changePassword(currentPassword, newPassword);
      setPasswordMsg({ type: 'success', text: res.message || (lang === 'pt' ? 'Senha alterada com sucesso!' : 'Password changed successfully!') });
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (e: any) {
      setPasswordMsg({ type: 'error', text: e.message || 'Falha ao alterar senha' });
    } finally {
      setSavingPassword(false);
    }
  };

  const handleStartTOTP = async () => {
    setTotpMsg(null);
    setTotpLoading(true);
    try {
      const setup = await api.setupTOTP();
      setTotpSetup(setup);
      const url = await QRCode.toDataURL(setup.otpauth_url, {
        margin: 1,
        width: 200,
        color: { dark: '#000000', light: '#ffffff' },
      });
      setQrCodeDataUrl(url);
    } catch (e: any) {
      setTotpMsg({ type: 'error', text: e.message || 'Falha ao inicializar 2FA' });
    } finally {
      setTotpLoading(false);
    }
  };

  const handleEnableTOTP = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!totpSetup || !totpCode) return;
    setTotpMsg(null);
    setTotpLoading(true);
    try {
      const res = await api.enableTOTP(totpSetup.secret, totpCode.trim());
      setTotpMsg({ type: 'success', text: res.message || '2FA ativado com sucesso!' });
      setTotpSetup(null);
      setQrCodeDataUrl(null);
      setTotpCode('');
      onUpdateUser({ ...currentUser, totp_enabled: true });
    } catch (e: any) {
      setTotpMsg({ type: 'error', text: e.message || 'Código TOTP incorreto' });
    } finally {
      setTotpLoading(false);
    }
  };

  const handleDisableTOTP = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!totpDisablePassword) return;
    setTotpMsg(null);
    setTotpLoading(true);
    try {
      const res = await api.disableTOTP(totpDisablePassword);
      setTotpMsg({ type: 'success', text: res.message || '2FA desativado' });
      setTotpDisablePassword('');
      onUpdateUser({ ...currentUser, totp_enabled: false });
    } catch (e: any) {
      setTotpMsg({ type: 'error', text: e.message || 'Senha incorreta para desativar 2FA' });
    } finally {
      setTotpLoading(false);
    }
  };

  const handleCopySecret = () => {
    if (!totpSetup) return;
    navigator.clipboard.writeText(totpSetup.secret);
    setCopiedSecret(true);
    setTimeout(() => setCopiedSecret(false), 2000);
  };

  const handleRevokeSession = async (id: string) => {
    if (!confirm(lang === 'pt' ? 'Deseja encerrar esta sessão?' : 'Revoke this session?')) return;
    try {
      await api.revokeSession(id);
      setSessions((prev) => prev.filter((s) => s.id !== id));
    } catch (e: any) {
      alert(e.message || 'Falha ao revogar sessão');
    }
  };

  const handleTestOIDC = async () => {
    if (!oidcConfig.issuer_url) {
      setOidcMsg({ type: 'error', text: lang === 'pt' ? 'Informe o Issuer URL antes de testar' : 'Provide Issuer URL before testing' });
      return;
    }
    setTestingOIDC(true);
    setOidcTestResult(null);
    setOidcMsg(null);
    try {
      const result = await api.testOIDCSettings(oidcConfig.issuer_url);
      setOidcTestResult(result);
      setOidcMsg({ type: 'success', text: lang === 'pt' ? 'Descoberta OIDC realizada com sucesso!' : 'OIDC Discovery successful!' });
    } catch (e: any) {
      setOidcMsg({ type: 'error', text: e.message || 'Falha na descoberta OIDC' });
    } finally {
      setTestingOIDC(false);
    }
  };

  const handleSaveOIDC = async (e: React.FormEvent) => {
    e.preventDefault();
    setOidcLoading(true);
    setOidcMsg(null);
    try {
      const res = await api.saveOIDCSettings(oidcConfig);
      setOidcMsg({ type: 'success', text: res.message || 'Configurações OIDC salvas!' });
    } catch (e: any) {
      setOidcMsg({ type: 'error', text: e.message || 'Erro ao salvar OIDC' });
    } finally {
      setOidcLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn">
      <div className="bg-zinc-950 border border-zinc-800 rounded-2xl w-full max-w-3xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-zinc-800 flex items-center justify-between bg-black/50">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-white flex items-center gap-2">
                <span>{lang === 'pt' ? 'Segurança & Conta' : 'Account & Security'}</span>
                <span
                  className={`text-[10px] font-mono px-2 py-0.5 rounded-full font-bold uppercase ${
                    currentUser.role === 'admin'
                      ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                      : 'bg-zinc-800 text-zinc-300 border border-zinc-700'
                  }`}
                >
                  {currentUser.role}
                </span>
              </h2>
              <div className="text-xs text-zinc-400 font-mono">
                {currentUser.username} • {currentUser.auth_type.toUpperCase()}
              </div>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-zinc-400 hover:text-white hover:bg-zinc-900 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tabs Bar */}
        <div className="flex border-b border-zinc-800 bg-zinc-900/40 px-6 gap-1 overflow-x-auto text-sm">
          <button
            onClick={() => setActiveTab('profile')}
            className={`px-4 py-3 font-medium border-b-2 transition flex items-center gap-2 whitespace-nowrap ${
              activeTab === 'profile'
                ? 'border-amber-500 text-amber-400'
                : 'border-transparent text-zinc-400 hover:text-zinc-200'
            }`}
          >
            <UserIcon className="w-4 h-4" />
            <span>{lang === 'pt' ? 'Perfil & Senha' : 'Profile & Password'}</span>
          </button>

          <button
            onClick={() => setActiveTab('2fa')}
            className={`px-4 py-3 font-medium border-b-2 transition flex items-center gap-2 whitespace-nowrap ${
              activeTab === '2fa'
                ? 'border-amber-500 text-amber-400'
                : 'border-transparent text-zinc-400 hover:text-zinc-200'
            }`}
          >
            <Smartphone className="w-4 h-4" />
            <span>{lang === 'pt' ? 'Autenticação 2FA' : '2FA Security'}</span>
            {currentUser.totp_enabled && (
              <span className="w-2 h-2 rounded-full bg-amber-400 animate-pulse" />
            )}
          </button>

          <button
            onClick={() => setActiveTab('sessions')}
            className={`px-4 py-3 font-medium border-b-2 transition flex items-center gap-2 whitespace-nowrap ${
              activeTab === 'sessions'
                ? 'border-amber-500 text-amber-400'
                : 'border-transparent text-zinc-400 hover:text-zinc-200'
            }`}
          >
            <Laptop className="w-4 h-4" />
            <span>{lang === 'pt' ? 'Sessões Ativas' : 'Active Sessions'}</span>
          </button>

          {currentUser.role === 'admin' && (
            <button
              onClick={() => setActiveTab('oidc')}
              className={`px-4 py-3 font-medium border-b-2 transition flex items-center gap-2 whitespace-nowrap ${
                activeTab === 'oidc'
                  ? 'border-amber-500 text-amber-400'
                  : 'border-transparent text-zinc-400 hover:text-zinc-200'
              }`}
            >
              <Globe className="w-4 h-4 text-amber-500" />
              <span>{lang === 'pt' ? 'OpenID SSO (Admin)' : 'OpenID SSO (Admin)'}</span>
            </button>
          )}
        </div>

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* TAB 1: PROFILE & PASSWORD */}
          {activeTab === 'profile' && (
            <div className="space-y-6 max-w-xl">
              <div className="bg-zinc-900/50 border border-zinc-800/80 rounded-xl p-4">
                <h3 className="text-xs uppercase font-mono text-zinc-400 font-bold mb-3">
                  {lang === 'pt' ? 'Identidade do Operador' : 'Operator Identity'}
                </h3>
                <div className="grid grid-cols-2 gap-4 text-xs font-mono">
                  <div>
                    <span className="text-zinc-500 block mb-0.5">{lang === 'pt' ? 'Usuário:' : 'Username:'}</span>
                    <span className="text-zinc-200 font-bold">{currentUser.username}</span>
                  </div>
                  <div>
                    <span className="text-zinc-500 block mb-0.5">{lang === 'pt' ? 'Nível de Acesso (RBAC):' : 'Role (RBAC):'}</span>
                    <span className="text-amber-400 font-bold uppercase">{currentUser.role}</span>
                  </div>
                  <div>
                    <span className="text-zinc-500 block mb-0.5">{lang === 'pt' ? 'Tipo de Autenticação:' : 'Auth Type:'}</span>
                    <span className="text-zinc-300">{currentUser.auth_type === 'local' ? 'Local (Argon2id)' : 'OpenID Connect'}</span>
                  </div>
                  <div>
                    <span className="text-zinc-500 block mb-0.5">{lang === 'pt' ? 'Status 2FA TOTP:' : '2FA TOTP Status:'}</span>
                    <span className={currentUser.totp_enabled ? 'text-amber-400 font-bold' : 'text-zinc-400'}>
                      {currentUser.totp_enabled ? (lang === 'pt' ? 'Ativado' : 'Enabled') : (lang === 'pt' ? 'Desativado' : 'Disabled')}
                    </span>
                  </div>
                </div>
              </div>

              {currentUser.auth_type === 'local' ? (
                <form onSubmit={handlePasswordChange} className="space-y-4">
                  <h3 className="text-sm font-bold text-white flex items-center gap-2">
                    <Key className="w-4 h-4 text-amber-500" />
                    <span>{lang === 'pt' ? 'Alterar Senha Local (Argon2id)' : 'Change Local Password (Argon2id)'}</span>
                  </h3>

                  {passwordMsg && (
                    <div
                      className={`p-3 rounded-lg text-xs flex items-center gap-2 ${
                        passwordMsg.type === 'success'
                          ? 'bg-amber-950/40 border border-amber-800/60 text-amber-200'
                          : 'bg-red-950/40 border border-red-800/60 text-red-300'
                      }`}
                    >
                      {passwordMsg.type === 'success' ? (
                        <CheckCircle2 className="w-4 h-4 text-amber-400 shrink-0" />
                      ) : (
                        <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
                      )}
                      <span>{passwordMsg.text}</span>
                    </div>
                  )}

                  <div>
                    <label className="block text-xs font-mono text-zinc-300 mb-1">
                      {lang === 'pt' ? 'Senha Atual' : 'Current Password'}
                    </label>
                    <input
                      type="password"
                      required
                      value={currentPassword}
                      onChange={(e) => setCurrentPassword(e.target.value)}
                      className="w-full bg-black/60 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-zinc-100 placeholder-zinc-600 focus:outline-none focus:border-amber-500 font-mono"
                    />
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-xs font-mono text-zinc-300 mb-1">
                        {lang === 'pt' ? 'Nova Senha' : 'New Password'}
                      </label>
                      <input
                        type="password"
                        required
                        value={newPassword}
                        onChange={(e) => setNewPassword(e.target.value)}
                        placeholder="Min. 8 caracteres"
                        className="w-full bg-black/60 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-zinc-100 placeholder-zinc-600 focus:outline-none focus:border-amber-500 font-mono"
                      />
                    </div>

                    <div>
                      <label className="block text-xs font-mono text-zinc-300 mb-1">
                        {lang === 'pt' ? 'Confirmar Nova Senha' : 'Confirm New Password'}
                      </label>
                      <input
                        type="password"
                        required
                        value={confirmPassword}
                        onChange={(e) => setConfirmPassword(e.target.value)}
                        className="w-full bg-black/60 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-zinc-100 placeholder-zinc-600 focus:outline-none focus:border-amber-500 font-mono"
                      />
                    </div>
                  </div>

                  <button
                    type="submit"
                    disabled={savingPassword}
                    className="bg-amber-600 hover:bg-amber-500 text-black font-bold px-4 py-2 rounded-lg text-xs transition disabled:opacity-50 flex items-center gap-2 font-mono"
                  >
                    {savingPassword ? (
                      <span className="inline-block w-3 h-3 border-2 border-black border-t-transparent rounded-full animate-spin" />
                    ) : (
                      <span>{lang === 'pt' ? 'Atualizar Senha' : 'Update Password'}</span>
                    )}
                  </button>
                </form>
              ) : (
                <div className="p-4 rounded-xl bg-zinc-900 border border-zinc-800 text-xs text-zinc-400">
                  {lang === 'pt'
                    ? 'Esta conta autentica via OpenID Connect federado. A gestão de credenciais e senhas deve ser realizada diretamente no seu provedor de identidade (IdP).'
                    : 'This account authenticates via federated OpenID Connect. Credential management must be performed directly in your Identity Provider (IdP).'}
                </div>
              )}
            </div>
          )}

          {/* TAB 2: TWO-FACTOR AUTHENTICATION (TOTP) */}
          {activeTab === '2fa' && (
            <div className="space-y-6 max-w-xl">
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <Smartphone className="w-4 h-4 text-amber-500" />
                  <span>{lang === 'pt' ? 'Autenticação de Dois Fatores (TOTP RFC 6238)' : 'Two-Factor Authentication (TOTP RFC 6238)'}</span>
                </h3>
                <p className="text-xs text-zinc-400 mt-1">
                  {lang === 'pt'
                    ? 'Compatível com Google Authenticator, Microsoft Authenticator, 1Password, Bitwarden e FreeOTP.'
                    : 'Compatible with Google Authenticator, Microsoft Authenticator, 1Password, Bitwarden, and FreeOTP.'}
                </p>
              </div>

              {totpMsg && (
                <div
                  className={`p-3 rounded-lg text-xs flex items-center gap-2 ${
                    totpMsg.type === 'success'
                      ? 'bg-amber-950/40 border border-amber-800/60 text-amber-200'
                      : 'bg-red-950/40 border border-red-800/60 text-red-300'
                  }`}
                >
                  {totpMsg.type === 'success' ? (
                    <CheckCircle2 className="w-4 h-4 text-amber-400 shrink-0" />
                  ) : (
                    <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
                  )}
                  <span>{totpMsg.text}</span>
                </div>
              )}

              {currentUser.totp_enabled ? (
                <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-5 space-y-4">
                  <div className="flex items-center gap-3">
                    <CheckCircle2 className="w-6 h-6 text-amber-400 shrink-0" />
                    <div>
                      <div className="text-sm font-bold text-amber-200">
                        {lang === 'pt' ? '2FA Ativado e Protegido' : '2FA Enabled and Protected'}
                      </div>
                      <div className="text-xs text-zinc-400">
                        {lang === 'pt'
                          ? 'Sua conta requer código de 6 dígitos gerado pelo aplicativo autenticador a cada login.'
                          : 'Your account requires a 6-digit code generated by your authenticator app at each sign in.'}
                      </div>
                    </div>
                  </div>

                  {currentUser.auth_type === 'local' && (
                    <form onSubmit={handleDisableTOTP} className="pt-4 border-t border-amber-500/20 space-y-3">
                      <div className="text-xs font-mono text-zinc-300">
                        {lang === 'pt' ? 'Para desativar o 2FA, confirme sua senha local:' : 'To disable 2FA, confirm your local password:'}
                      </div>
                      <div className="flex gap-2">
                        <input
                          type="password"
                          required
                          value={totpDisablePassword}
                          onChange={(e) => setTotpDisablePassword(e.target.value)}
                          placeholder="••••••••"
                          className="flex-1 bg-black/80 border border-zinc-800 rounded-lg px-3 py-1.5 text-xs text-zinc-100 placeholder-zinc-600 focus:outline-none focus:border-red-500 font-mono"
                        />
                        <button
                          type="submit"
                          disabled={totpLoading}
                          className="bg-red-950/60 hover:bg-red-900 border border-red-800 text-red-200 font-mono text-xs px-3 py-1.5 rounded-lg transition disabled:opacity-50"
                        >
                          {lang === 'pt' ? 'Desativar 2FA' : 'Disable 2FA'}
                        </button>
                      </div>
                    </form>
                  )}
                </div>
              ) : (
                <div className="space-y-4">
                  {!totpSetup ? (
                    <div className="bg-zinc-900/50 border border-zinc-800 rounded-xl p-5 text-center space-y-3">
                      <div className="text-xs text-zinc-400 max-w-md mx-auto">
                        {lang === 'pt'
                          ? 'A ativação do 2FA adiciona uma camada vital de segurança contra acessos não autorizados ao controle de firewall dos seus servidores.'
                          : 'Enabling 2FA adds a critical layer of defense protecting your servers from unauthorized firewall access.'}
                      </div>
                      <button
                        onClick={handleStartTOTP}
                        disabled={totpLoading}
                        className="bg-amber-600 hover:bg-amber-500 text-black font-bold px-4 py-2 rounded-lg text-xs font-mono transition"
                      >
                        {lang === 'pt' ? 'Configurar Autenticação em 2 Etapas' : 'Setup Two-Factor Authentication'}
                      </button>
                    </div>
                  ) : (
                    <div className="bg-zinc-900/60 border border-zinc-800 rounded-xl p-5 space-y-5 animate-fadeIn">
                      <div className="flex flex-col sm:flex-row items-center gap-6">
                        {qrCodeDataUrl && (
                          <div className="bg-white p-2 rounded-xl shadow-lg border-2 border-amber-500/50 shrink-0">
                            <img src={qrCodeDataUrl} alt="2FA QR Code" className="w-36 h-36" />
                          </div>
                        )}
                        <div className="space-y-3 flex-1">
                          <div className="text-xs text-zinc-300">
                            <strong>1.</strong>{' '}
                            {lang === 'pt'
                              ? 'Escaneie o QR Code com seu aplicativo autenticador favorito.'
                              : 'Scan the QR Code with your authenticator app.'}
                          </div>

                          <div className="text-xs text-zinc-400">
                            <strong>2.</strong>{' '}
                            {lang === 'pt' ? 'Ou insira a chave secreta manualmente:' : 'Or enter secret key manually:'}
                          </div>

                          <div className="flex items-center gap-2 bg-black/60 border border-zinc-800 rounded-lg p-2 font-mono text-xs text-amber-300">
                            <span className="flex-1 break-all select-all">{totpSetup.secret}</span>
                            <button
                              type="button"
                              onClick={handleCopySecret}
                              className="p-1 rounded hover:bg-zinc-800 text-zinc-400 hover:text-white transition"
                              title="Copiar"
                            >
                              {copiedSecret ? <Check className="w-4 h-4 text-amber-400" /> : <Copy className="w-4 h-4" />}
                            </button>
                          </div>
                        </div>
                      </div>

                      {/* Confirmation form */}
                      <form onSubmit={handleEnableTOTP} className="pt-4 border-t border-zinc-800 flex flex-col sm:flex-row items-center gap-3">
                        <div className="w-full sm:flex-1">
                          <label className="block text-xs font-mono text-zinc-300 mb-1">
                            {lang === 'pt' ? '3. Digite o código de 6 dígitos para validar:' : '3. Enter 6-digit code to verify:'}
                          </label>
                          <input
                            type="text"
                            required
                            maxLength={6}
                            value={totpCode}
                            onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ''))}
                            placeholder="000000"
                            className="w-full bg-black/80 border border-amber-500/60 rounded-lg px-3 py-2 text-sm text-center text-amber-200 font-mono tracking-widest focus:outline-none"
                          />
                        </div>
                        <div className="w-full sm:w-auto self-end">
                          <button
                            type="submit"
                            disabled={totpLoading || totpCode.length !== 6}
                            className="w-full sm:w-auto bg-amber-600 hover:bg-amber-500 text-black font-bold px-4 py-2 rounded-lg text-xs font-mono transition disabled:opacity-50"
                          >
                            {lang === 'pt' ? 'Ativar 2FA' : 'Activate 2FA'}
                          </button>
                        </div>
                      </form>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* TAB 3: ACTIVE SESSIONS */}
          {activeTab === 'sessions' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-bold text-white flex items-center gap-2">
                    <Laptop className="w-4 h-4 text-amber-500" />
                    <span>{lang === 'pt' ? 'Sessões Ativas do Usuário' : 'Active User Sessions'}</span>
                  </h3>
                  <p className="text-xs text-zinc-400 mt-0.5">
                    {lang === 'pt'
                      ? 'Dispositivos e navegadores atualmente autenticados com sua credencial.'
                      : 'Devices and browsers currently logged into your account.'}
                  </p>
                </div>
                <button
                  onClick={loadSessions}
                  disabled={sessionsLoading}
                  className="p-1.5 rounded-lg border border-zinc-800 hover:border-zinc-700 bg-zinc-900 text-zinc-300 hover:text-white transition text-xs flex items-center gap-1 font-mono"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${sessionsLoading ? 'animate-spin' : ''}`} />
                  <span>{lang === 'pt' ? 'Atualizar' : 'Refresh'}</span>
                </button>
              </div>

              {sessions.length === 0 ? (
                <div className="text-center py-8 text-zinc-500 text-xs font-mono">
                  {lang === 'pt' ? 'Nenhuma sessão ativa encontrada.' : 'No active sessions found.'}
                </div>
              ) : (
                <div className="space-y-2">
                  {sessions.map((sess) => (
                    <div
                      key={sess.id}
                      className="bg-zinc-900/60 border border-zinc-800/80 rounded-xl p-3 flex items-center justify-between gap-3 text-xs font-mono"
                    >
                      <div className="flex items-center gap-3">
                        <div className="w-8 h-8 rounded-lg bg-zinc-800 flex items-center justify-center text-zinc-400">
                          <Laptop className="w-4 h-4" />
                        </div>
                        <div>
                          <div className="text-zinc-200 font-bold flex items-center gap-2">
                            <span>{sess.ip_address}</span>
                          </div>
                          <div className="text-[11px] text-zinc-500 truncate max-w-md">
                            {sess.user_agent || 'HTTP Client / Browser'}
                          </div>
                          <div className="text-[10px] text-zinc-600 mt-0.5">
                            {lang === 'pt' ? 'Iniciada:' : 'Started:'} {new Date(sess.created_at).toLocaleString()}
                          </div>
                        </div>
                      </div>

                      <button
                        onClick={() => handleRevokeSession(sess.id)}
                        className="px-2.5 py-1 rounded bg-zinc-950 hover:bg-red-950/60 border border-zinc-800 hover:border-red-800 text-zinc-400 hover:text-red-300 transition text-[11px]"
                      >
                        {lang === 'pt' ? 'Revogar' : 'Revoke'}
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* TAB 4: OPENID CONNECT SSO (ADMIN ONLY) */}
          {activeTab === 'oidc' && currentUser.role === 'admin' && (
            <div className="space-y-6 max-w-xl">
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <Globe className="w-4 h-4 text-amber-500" />
                  <span>{lang === 'pt' ? 'Configuração de OpenID Connect (SSO Corporativo)' : 'OpenID Connect Configuration (Corporate SSO)'}</span>
                </h3>
                <p className="text-xs text-zinc-400 mt-1">
                  {lang === 'pt'
                    ? 'Permite autenticação federada via Google Workspace, Keycloak, Okta, Microsoft Entra ID ou qualquer IdP OIDC padrão.'
                    : 'Enables federated single sign-on with Google Workspace, Keycloak, Okta, Microsoft Entra ID, or any standard OIDC IdP.'}
                </p>
              </div>

              {oidcMsg && (
                <div
                  className={`p-3 rounded-lg text-xs flex items-center gap-2 ${
                    oidcMsg.type === 'success'
                      ? 'bg-amber-950/40 border border-amber-800/60 text-amber-200'
                      : 'bg-red-950/40 border border-red-800/60 text-red-300'
                  }`}
                >
                  {oidcMsg.type === 'success' ? (
                    <CheckCircle2 className="w-4 h-4 text-amber-400 shrink-0" />
                  ) : (
                    <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
                  )}
                  <span>{oidcMsg.text}</span>
                </div>
              )}

              <form onSubmit={handleSaveOIDC} className="space-y-4">
                {/* Enabled checkbox */}
                <div className="flex items-center gap-3 p-3 bg-zinc-900/60 border border-zinc-800 rounded-xl">
                  <input
                    type="checkbox"
                    id="oidc_enabled"
                    checked={oidcConfig.enabled}
                    onChange={(e) => setOidcConfig({ ...oidcConfig, enabled: e.target.checked })}
                    className="w-4 h-4 accent-amber-500 rounded cursor-pointer"
                  />
                  <label htmlFor="oidc_enabled" className="text-xs font-mono font-medium text-zinc-200 cursor-pointer">
                    {lang === 'pt' ? 'Habilitar autenticação federada OpenID Connect' : 'Enable OpenID Connect federated authentication'}
                  </label>
                </div>

                <div>
                  <label className="block text-xs font-mono text-zinc-300 mb-1">
                    {lang === 'pt' ? 'Nome de Exibição do Provedor (Botão no Login)' : 'Provider Display Name (Login Button)'}
                  </label>
                  <input
                    type="text"
                    required
                    value={oidcConfig.provider_name}
                    onChange={(e) => setOidcConfig({ ...oidcConfig, provider_name: e.target.value })}
                    placeholder="ex: Google Workspace / Keycloak Corp"
                    className="w-full bg-black/60 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-zinc-100 placeholder-zinc-600 focus:outline-none focus:border-amber-500 font-mono"
                  />
                </div>

                <div>
                  <div className="flex items-center justify-between mb-1">
                    <label className="block text-xs font-mono text-zinc-300">
                      {lang === 'pt' ? 'Issuer URL (OIDC Provider)' : 'Issuer URL (OIDC Provider)'}
                    </label>
                    <button
                      type="button"
                      onClick={handleTestOIDC}
                      disabled={testingOIDC || !oidcConfig.issuer_url}
                      className="text-amber-400 hover:text-amber-300 text-[11px] font-mono underline transition disabled:opacity-40"
                    >
                      {testingOIDC ? 'Testando...' : (lang === 'pt' ? '🔍 Testar Descoberta (Well-Known)' : '🔍 Test Discovery (Well-Known)')}
                    </button>
                  </div>
                  <input
                    type="url"
                    value={oidcConfig.issuer_url}
                    onChange={(e) => setOidcConfig({ ...oidcConfig, issuer_url: e.target.value })}
                    placeholder="https://accounts.google.com ou https://auth.dominio.com/realms/master"
                    className="w-full bg-black/60 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-zinc-100 placeholder-zinc-600 focus:outline-none focus:border-amber-500 font-mono"
                  />
                </div>

                {/* Discovery Test Result Box */}
                {oidcTestResult && (
                  <div className="p-3 rounded-lg bg-zinc-900 border border-amber-500/30 text-xs font-mono space-y-1.5 animate-fadeIn">
                    <div className="text-amber-400 font-bold flex items-center gap-1.5">
                      <Check className="w-3.5 h-3.5" />
                      <span>{lang === 'pt' ? 'Configuração OIDC Detectada:' : 'Detected OIDC Configuration:'}</span>
                    </div>
                    <div className="text-[11px] text-zinc-300">
                      <strong>Auth Endpoint:</strong> <span className="text-zinc-400">{oidcTestResult.authorization_endpoint}</span>
                    </div>
                    <div className="text-[11px] text-zinc-300">
                      <strong>Token Endpoint:</strong> <span className="text-zinc-400">{oidcTestResult.token_endpoint}</span>
                    </div>
                  </div>
                )}

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-xs font-mono text-zinc-300 mb-1">
                      Client ID
                    </label>
                    <input
                      type="text"
                      value={oidcConfig.client_id}
                      onChange={(e) => setOidcConfig({ ...oidcConfig, client_id: e.target.value })}
                      placeholder="client-id"
                      className="w-full bg-black/60 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-zinc-100 placeholder-zinc-600 focus:outline-none focus:border-amber-500 font-mono"
                    />
                  </div>

                  <div>
                    <label className="block text-xs font-mono text-zinc-300 mb-1">
                      Client Secret
                    </label>
                    <div className="relative">
                      <input
                        type={showClientSecret ? 'text' : 'password'}
                        value={oidcConfig.client_secret || ''}
                        onChange={(e) => setOidcConfig({ ...oidcConfig, client_secret: e.target.value })}
                        placeholder="••••••••••••"
                        className="w-full bg-black/60 border border-zinc-800 rounded-lg pl-3 pr-8 py-2 text-sm text-zinc-100 placeholder-zinc-600 focus:outline-none focus:border-amber-500 font-mono"
                      />
                      <button
                        type="button"
                        onClick={() => setShowClientSecret(!showClientSecret)}
                        className="absolute inset-y-0 right-0 pr-2.5 flex items-center text-zinc-500 hover:text-zinc-300"
                      >
                        {showClientSecret ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-xs font-mono text-zinc-300 mb-1">
                      {lang === 'pt' ? 'Role Padrão para Novos Usuários' : 'Default Role for New Users'}
                    </label>
                    <select
                      value={oidcConfig.default_role}
                      onChange={(e) => setOidcConfig({ ...oidcConfig, default_role: e.target.value as 'admin' | 'viewer' })}
                      className="w-full bg-black border border-zinc-800 rounded-lg px-3 py-2 text-sm text-zinc-100 focus:outline-none focus:border-amber-500 font-mono"
                    >
                      <option value="viewer">{lang === 'pt' ? 'viewer (Somente Leitura)' : 'viewer (Read-Only)'}</option>
                      <option value="admin">{lang === 'pt' ? 'admin (Acesso Total)' : 'admin (Full Access)'}</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-xs font-mono text-zinc-300 mb-1">
                      Scopes
                    </label>
                    <input
                      type="text"
                      value={oidcConfig.scopes}
                      onChange={(e) => setOidcConfig({ ...oidcConfig, scopes: e.target.value })}
                      placeholder="openid profile email"
                      className="w-full bg-black/60 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-zinc-100 placeholder-zinc-600 focus:outline-none focus:border-amber-500 font-mono"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-mono text-zinc-400 mb-1">
                    {lang === 'pt' ? 'URL de Retorno Autorizada (Configure no seu IdP):' : 'Authorized Callback URL (Set in your IdP):'}
                  </label>
                  <div className="bg-black/60 border border-zinc-800 rounded-lg px-3 py-1.5 text-xs text-zinc-400 font-mono select-all">
                    {window.location.origin}/api/v1/auth/oidc/callback
                  </div>
                </div>

                <div className="pt-2">
                  <button
                    type="submit"
                    disabled={oidcLoading}
                    className="bg-amber-600 hover:bg-amber-500 text-black font-bold px-4 py-2.5 rounded-lg text-xs font-mono transition disabled:opacity-50"
                  >
                    {oidcLoading ? 'Salvando...' : (lang === 'pt' ? 'Salvar Configurações OIDC' : 'Save OIDC Configuration')}
                  </button>
                </div>
              </form>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
