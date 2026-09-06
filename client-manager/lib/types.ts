export interface ClientConfig {
  clientId: string;
  clientName: string;
  clientAuthenticationMethods: string[];
  authorizationGrantTypes: string[];
  redirectUris: string[];
  postLogoutRedirectUris: string[];
  scopes: string[];
  requireProofKey: boolean;
  requireAuthorizationConsent: boolean;
  accessTokenTimeToLiveMinutes: number;
  refreshTokenTimeToLiveDays: number;
  publicKeyPem: string;
}

export const AVAILABLE_SCOPES = [
  { id: "openid", label: "openid", description: "Required for OpenID Connect 1.0 identity tokens" },
  { id: "profile", label: "profile", description: "Access to user profile (name, username)" },
  { id: "email", label: "email", description: "Access to user email address" },
  { id: "user.read", label: "user.read", description: "Standard user resource reading" },
  { id: "demo.secret_access", label: "demo.secret_access", description: "Privileged scope granting restricted UserInfo clearance claims" },
];
