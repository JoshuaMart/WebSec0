// API payload types shared by the report and its presentation helpers.

export type Grade = 'A+' | 'A' | 'B' | 'C' | 'D' | 'E' | 'F' | 'T' | '';
export type Status = 'pass' | 'fail' | 'warn' | 'info' | '';
export type Severity = 'good' | 'warn' | 'bad' | 'info';

export type ProtocolSupport = { name: string; offered: boolean; probe: string };
export type TLSScanStatus = '' | 'complete' | 'partial_blocked';
export type Cipher = {
  protocol: string;
  name: string;
  code: string;
  strength: number;
  aead: boolean;
  pfs: boolean;
  level: Severity;
};
export type Certificate = {
  step: number;
  kind: string;
  cn: string;
  issuer: string;
  not_before: string;
  not_after: string;
  days_left: number;
  key_alg: string;
  sig_alg: string;
  serial: string;
  sha256: string;
  san: string[];
  revocation: string;
};
export type Vuln = {
  id: string;
  title: string;
  cve?: string;
  state: string;
  level: Severity;
  body: string;
};
export type HeaderResult = { present: boolean; value?: string; status: Status };
export type CookieResult = {
  name: string;
  secure: boolean;
  httponly: boolean;
  samesite: string | null;
  status: Status;
};
export type HandshakeSCTs = {
  count: number;
  log_ids: string[];
  unparsed_count: number;
};
export type TLSReport = {
  grade: Grade;
  scores: {
    certificate: number;
    protocol_support: number;
    key_exchange: number;
    cipher_strength: number;
    final: number;
  };
  protocols: ProtocolSupport[];
  ciphers: Cipher[];
  cipher_preference?: 'server' | 'client' | '';
  certificate_chain: Certificate[];
  chain_trust: string;
  ocsp_stapling: boolean;
  ocsp_status?: string;
  handshake_scts?: HandshakeSCTs;
  session_resumption?: string;
  vulnerabilities: Vuln[];
  scan_status?: TLSScanStatus;
};
export type HeadersReport = {
  grade: Grade;
  score: number;
  core: Record<string, HeaderResult>;
  additional: {
    server?: HeaderResult;
    'set-cookie'?: CookieResult[];
    'access-control-allow-origin'?: HeaderResult;
    'cross-origin-opener-policy'?: HeaderResult;
    'cross-origin-embedder-policy'?: HeaderResult;
    'cross-origin-resource-policy'?: HeaderResult;
  };
  probed_host?: string;
};
export type CustomFinding = {
  id: string;
  title: string;
  status: Status;
  details?: Record<string, unknown>;
};
export type ScanResult = {
  id: string;
  host: string;
  port: number;
  resolved_ip: string;
  scanned_at: string;
  duration_ms: number;
  tls?: TLSReport;
  headers?: HeadersReport;
  custom?: CustomFinding[];
};
