import type { Envelope } from "./crypto";

export interface UiConfig {
  product_name: string;
  company_name: string;
  tagline: string;
  support_url: string;
  footer_text: string;
  show_powered_by: boolean;
  has_logo: boolean;
  has_favicon: boolean;
  colors: {
    primary: string;
    on_primary: string;
    secondary: string;
    surface: string;
    on_surface: string;
    surface_variant: string;
    error: string;
  };
  ttl_options_seconds: number[];
  default_ttl_seconds: number;
  max_plaintext_bytes: number;
  kdf_iterations: number;
  max_failed_proofs: number;
  mode: "standard" | "enterprise";
  creation_requires_sign_in: boolean;
  consumption_requires_sign_in: boolean;
  recipient_must_match: boolean;
  version: string;
}

export interface SessionView {
  authenticated: boolean;
  email?: string;
  subject?: string;
}

export interface CreateRequest {
  sender: string;
  recipient: string;
  ttl_seconds: number;
  verifier: string;
  envelope: Envelope;
}

export interface CreateResponse {
  id: string;
  revoke_token: string;
  expires_at: string;
}

export interface ConsumeResponse {
  sender: string;
  recipient: string;
  created_at: string;
  envelope: Envelope;
}

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

async function request<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(path, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify(body),
    credentials: "same-origin",
    cache: "no-store",
    referrerPolicy: "no-referrer",
  });
  if (res.status === 204) return undefined as T;
  let payload: unknown = null;
  try {
    payload = await res.json();
  } catch {
    payload = null;
  }
  if (!res.ok) {
    const message =
      payload && typeof payload === "object" && "error" in payload && typeof (payload as { error: unknown }).error === "string"
        ? (payload as { error: string }).error
        : `request failed (${res.status})`;
    throw new ApiError(res.status, message);
  }
  return payload as T;
}

export async function loadUiConfig(): Promise<UiConfig> {
  const res = await fetch("/v1/ui-config", { cache: "no-store", credentials: "same-origin" });
  if (!res.ok) throw new ApiError(res.status, "could not load configuration");
  return (await res.json()) as UiConfig;
}

export async function loadSession(): Promise<SessionView> {
  const res = await fetch("/v1/session", { cache: "no-store", credentials: "same-origin" });
  if (!res.ok) return { authenticated: false };
  return (await res.json()) as SessionView;
}

export async function logout(): Promise<void> {
  await fetch("/auth/logout", { method: "POST", credentials: "same-origin", cache: "no-store" });
}

export const api = {
  create: (body: CreateRequest) => request<CreateResponse>("/v1/messages", body),
  consume: (id: string, proof: string) => request<ConsumeResponse>(`/v1/messages/${encodeURIComponent(id)}/consume`, { proof }),
  revoke: (id: string, revokeToken: string) =>
    request<void>(`/v1/messages/${encodeURIComponent(id)}/revoke`, { revoke_token: revokeToken }),
};
