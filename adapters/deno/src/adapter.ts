import {
  handleWebRequest,
  NODE_EVENT_MEDIA_TYPE,
  type NodeCoreFetcher,
} from "../../shared/web-ingress.ts";

const DEFAULT_TIMEOUT_MILLISECONDS = 5_000;
const MAXIMUM_TIMEOUT_MILLISECONDS = 30_000;
const MAXIMUM_BEARER_TOKEN_BYTES = 8 * 1024;

export type DenoFetch = (request: Request) => Promise<Response>;

export interface DenoIngressConfig {
  readonly nodeCoreUrl: string;
  readonly bearerToken: string;
  readonly timeoutMilliseconds?: number;
  readonly fetch?: DenoFetch;
}

/** Builds an immutable Deno handler around an authenticated node-core client. */
export function createDenoHandler(
  config: DenoIngressConfig,
): (request: Request) => Promise<Response> {
  const nodeCore = new DenoNodeCoreFetcher(config);
  return (request) => handleWebRequest(request, nodeCore);
}

class DenoNodeCoreFetcher implements NodeCoreFetcher {
  readonly #endpoint: URL;
  readonly #bearerToken: string;
  readonly #timeoutMilliseconds: number;
  readonly #fetch: DenoFetch;

  constructor(config: DenoIngressConfig) {
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
    throw new TypeError("SUNRISE_NODE_CORE_URL must be an absolute HTTPS URL");
  }
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.pathname !== "/v1/events" ||
    url.search !== "" ||
    url.hash !== ""
  ) {
    throw new TypeError(
      "SUNRISE_NODE_CORE_URL must be an exact HTTPS /v1/events endpoint",
    );
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
    throw new TypeError(
      "SUNRISE_NODE_CORE_BEARER_TOKEN must be a non-empty bounded token",
    );
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
      `SUNRISE_NODE_CORE_TIMEOUT_MS must be an integer from 1 to ${MAXIMUM_TIMEOUT_MILLISECONDS}`,
    );
  }
  return value;
}
