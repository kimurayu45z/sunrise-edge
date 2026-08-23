import {
  NODE_EVENT_MEDIA_TYPE,
  type NodeCoreFetcher,
} from "./web-ingress.ts";

const DEFAULT_TIMEOUT_MILLISECONDS = 5_000;
const MAXIMUM_TIMEOUT_MILLISECONDS = 30_000;
const MAXIMUM_BEARER_TOKEN_BYTES = 8 * 1024;

export type WebFetch = (request: Request) => Promise<Response>;

export interface AuthenticatedNodeCoreConfig {
  readonly nodeCoreUrl: string;
  readonly bearerToken: string;
  readonly timeoutMilliseconds?: number;
  readonly fetch?: WebFetch;
}

/** Creates a bounded HTTPS/Bearer capability for the shared ingress core. */
export function createAuthenticatedNodeCoreFetcher(
  config: AuthenticatedNodeCoreConfig,
): NodeCoreFetcher {
  return new AuthenticatedNodeCoreFetcher(config);
}

class AuthenticatedNodeCoreFetcher implements NodeCoreFetcher {
  readonly #endpoint: URL;
  readonly #bearerToken: string;
  readonly #timeoutMilliseconds: number;
  readonly #fetch: WebFetch;

  constructor(config: AuthenticatedNodeCoreConfig) {
    this.#endpoint = validateNodeCoreUrl(config.nodeCoreUrl);
    this.#bearerToken = validateBearerToken(config.bearerToken);
    this.#timeoutMilliseconds = validateTimeout(
      config.timeoutMilliseconds ?? DEFAULT_TIMEOUT_MILLISECONDS,
    );
    this.#fetch = config.fetch ?? ((request) => fetch(request));
  }

  fetch(request: Request): Promise<Response> {
    if (
      request.method !== "POST" ||
      request.headers.get("content-type") !== NODE_EVENT_MEDIA_TYPE
    ) {
      throw new TypeError("shared ingress produced an invalid node-core request");
    }

    const upstreamRequest = new Request(this.#endpoint, {
      method: "POST",
      headers: {
        "authorization": `Bearer ${this.#bearerToken}`,
        "cache-control": "no-store",
        "content-type": NODE_EVENT_MEDIA_TYPE,
      },
      body: request.body,
      redirect: "error",
      signal: AbortSignal.timeout(this.#timeoutMilliseconds),
    });
    return this.#fetch(upstreamRequest);
  }
}

function validateNodeCoreUrl(value: string): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new TypeError("nodeCoreUrl must be an absolute HTTPS URL");
  }
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.pathname !== "/v1/events" ||
    url.search !== "" ||
    url.hash !== ""
  ) {
    throw new TypeError("nodeCoreUrl must be an exact HTTPS /v1/events endpoint");
  }
  return url;
}

function validateBearerToken(value: string): string {
  const bytes = new TextEncoder().encode(value);
  if (
    value.length === 0 ||
    value.trim() !== value ||
    bytes.some((byte) => byte < 0x21 || byte > 0x7e) ||
    bytes.byteLength > MAXIMUM_BEARER_TOKEN_BYTES
  ) {
    throw new TypeError("bearerToken must be a non-empty bounded ASCII token");
  }
  return value;
}

function validateTimeout(value: number): number {
  if (
    !Number.isSafeInteger(value) ||
    value <= 0 ||
    value > MAXIMUM_TIMEOUT_MILLISECONDS
  ) {
    throw new TypeError(
      `timeoutMilliseconds must be an integer from 1 to ${MAXIMUM_TIMEOUT_MILLISECONDS}`,
    );
  }
  return value;
}
