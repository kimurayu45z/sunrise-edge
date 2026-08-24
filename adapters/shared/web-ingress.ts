export const NODE_EVENT_PATH = "/v1/events";
export const LIVENESS_PATH = "/health/live";
export const NODE_EVENT_MEDIA_TYPE =
  "application/vnd.sunrise-edge.node-event";
export const NODE_RESULT_MEDIA_TYPE =
  "application/vnd.sunrise-edge.node-result";
export const MAX_HTTP_EVENT_BODY_BYTES = 16 * 1024 * 1024 + 512;

const NODE_CORE_URL = "https://node-core.internal/v1/events";

/** Minimum fetch capability required from a provider-specific node-core binding. */
export interface NodeCoreFetcher {
  fetch(request: Request): Promise<Response>;
}

export interface WebIngressOptions {
  /** A provider capacity limit that may narrow, but never raise, the protocol limit. */
  readonly maximumRequestBodyBytes?: number;
}

class IngressError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
  ) {
    super(code);
    this.name = "IngressError";
  }
}

/** Handles the shared Web Fetch API ingress contract for one provider binding. */
export async function handleWebRequest(
  request: Request,
  nodeCore: NodeCoreFetcher,
  options: WebIngressOptions = {},
): Promise<Response> {
  const maximumRequestBodyBytes = validateMaximumRequestBodyBytes(
    options.maximumRequestBodyBytes ?? MAX_HTTP_EVENT_BODY_BYTES,
  );
  const url = new URL(request.url);

  if (url.pathname === LIVENESS_PATH) {
    if (request.method !== "GET") {
      return methodNotAllowed("GET");
    }
    return new Response(null, {
      status: 204,
      headers: { "cache-control": "no-store" },
    });
  }
  if (url.pathname !== NODE_EVENT_PATH) {
    return errorResponse(404, "not-found");
  }
  if (request.method !== "POST") {
    return methodNotAllowed("POST");
  }

  try {
    validateHeaders(request.headers, maximumRequestBodyBytes);
    const body = await readBoundedBody(
      request.body,
      maximumRequestBodyBytes,
    );
    const downstreamRequest = new Request(NODE_CORE_URL, {
      method: "POST",
      headers: {
        "cache-control": "no-store",
        "content-type": NODE_EVENT_MEDIA_TYPE,
      },
      body,
    });
    const downstream = await nodeCore.fetch(downstreamRequest);
    if (downstream.status === 500) {
      await downstream.body?.cancel("node-core invocation failed");
      console.error(
        JSON.stringify({
          message: "node core returned an internal failure",
          method: request.method,
          path: url.pathname,
          status: downstream.status,
        }),
      );
      return errorResponse(502, "node-core-failure");
    }
    if (
      downstream.ok &&
      !hasExactMediaType(downstream.headers, NODE_RESULT_MEDIA_TYPE)
    ) {
      await downstream.body?.cancel("invalid node-core content type");
      return errorResponse(502, "invalid-node-core-response");
    }
    if (
      !downstream.ok &&
      downstream.headers.get("content-type") !== "text/plain; charset=utf-8"
    ) {
      await downstream.body?.cancel("invalid node-core error content type");
      return errorResponse(502, "invalid-node-core-response");
    }
    return sanitizeDownstreamResponse(downstream);
  } catch (error) {
    if (error instanceof IngressError) {
      return errorResponse(error.status, error.code);
    }
    console.error(
      JSON.stringify({
        message: "node core provider binding failed",
        method: request.method,
        path: url.pathname,
        error_kind: error instanceof Error ? error.name : "unknown",
      }),
    );
    return errorResponse(503, "node-core-unavailable");
  }
}

/** Reads at most `maximumBytes` from an incoming Web byte stream. */
export async function readBoundedBody(
  body: ReadableStream<Uint8Array> | null,
  maximumBytes: number,
): Promise<Uint8Array<ArrayBuffer>> {
  if (body === null) {
    throw new IngressError(400, "missing-body");
  }
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const result = await reader.read();
      if (result.done) {
        break;
      }
      if (result.value.byteLength > maximumBytes - total) {
        await reader.cancel("request body exceeds adapter limit");
        throw new IngressError(413, "body-too-large");
      }
      chunks.push(result.value);
      total += result.value.byteLength;
    }
  } finally {
    reader.releaseLock();
  }

  const output: Uint8Array<ArrayBuffer> = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output;
}

function validateMaximumRequestBodyBytes(value: number): number {
  if (
    !Number.isSafeInteger(value) ||
    value <= 0 ||
    value > MAX_HTTP_EVENT_BODY_BYTES
  ) {
    throw new TypeError(
      `maximumRequestBodyBytes must be an integer from 1 to ${MAX_HTTP_EVENT_BODY_BYTES}`,
    );
  }
  return value;
}

function validateHeaders(
  headers: Headers,
  maximumRequestBodyBytes: number,
): void {
  if (!hasExactMediaType(headers, NODE_EVENT_MEDIA_TYPE)) {
    throw new IngressError(415, "unsupported-content-type");
  }
  const contentEncoding = headers.get("content-encoding");
  if (
    contentEncoding !== null &&
    contentEncoding.trim().toLowerCase() !== "identity"
  ) {
    throw new IngressError(415, "unsupported-content-encoding");
  }
  const contentLength = headers.get("content-length")?.trim() ?? null;
  if (contentLength !== null) {
    if (!/^(0|[1-9][0-9]*)$/.test(contentLength)) {
      throw new IngressError(400, "invalid-content-length");
    }
    if (BigInt(contentLength) > BigInt(maximumRequestBodyBytes)) {
      throw new IngressError(413, "body-too-large");
    }
  }
}

function hasExactMediaType(headers: Headers, expected: string): boolean {
  return headers.get("content-type")?.trim().toLowerCase() === expected;
}

function sanitizeDownstreamResponse(response: Response): Response {
  const headers = new Headers({ "cache-control": "no-store" });
  const contentType = response.headers.get("content-type");
  if (contentType !== null) {
    headers.set("content-type", contentType);
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function methodNotAllowed(allow: string): Response {
  const response = errorResponse(405, "method-not-allowed");
  response.headers.set("allow", allow);
  return response;
}

function errorResponse(status: number, code: string): Response {
  return new Response(code, {
    status,
    headers: {
      "cache-control": "no-store",
      "content-type": "text/plain; charset=utf-8",
    },
  });
}
