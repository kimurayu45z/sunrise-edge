import { Buffer } from "node:buffer";
import { NODE_EVENT_PATH, type WebIngressOptions } from "../../shared/web-ingress.ts";

export const MAX_AWS_HTTP_API_REQUEST_BODY_BYTES = 4 * 1024 * 1024;
export const MAX_AWS_HTTP_API_RESPONSE_BODY_BYTES = 4 * 1024 * 1024;

export const AWS_HTTP_API_INGRESS_OPTIONS: WebIngressOptions = {
  maximumRequestBodyBytes: MAX_AWS_HTTP_API_REQUEST_BODY_BYTES,
};

export interface AwsHttpApiV2Result {
  readonly statusCode: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string;
  readonly isBase64Encoded: true;
}

interface ParsedHttpApiV2Event {
  readonly rawPath: string;
  readonly rawQueryString: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body?: string;
  readonly isBase64Encoded: boolean;
  readonly method: string;
}

class HttpApiEventError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string) {
    super(code);
    this.name = "HttpApiEventError";
    this.status = status;
    this.code = code;
  }
}

export async function handleAwsHttpApiV2Event(
  event: unknown,
  webHandler: (request: Request) => Promise<Response>,
): Promise<AwsHttpApiV2Result> {
  try {
    const request = eventToRequest(parseEvent(event));
    const response = await webHandler(request);
    return await responseToResult(response);
  } catch (error) {
    if (error instanceof HttpApiEventError) {
      return errorResult(error.status, error.code);
    }
    console.error(
      JSON.stringify({
        message: "AWS HTTP API adapter failed",
        error_kind: error instanceof Error ? error.name : "unknown",
      }),
    );
    return errorResult(500, "adapter-failure");
  }
}

function parseEvent(value: unknown): ParsedHttpApiV2Event {
  if (!isRecord(value) || value.version !== "2.0") {
    throw new HttpApiEventError(400, "invalid-http-api-event");
  }
  const requestContext = value.requestContext;
  if (!isRecord(requestContext) || !isRecord(requestContext.http)) {
    throw new HttpApiEventError(400, "invalid-http-api-event");
  }
  const method = requestContext.http.method;
  if (
    typeof method !== "string" ||
    !/^[A-Z]+$/u.test(method) ||
    typeof value.rawPath !== "string" ||
    !value.rawPath.startsWith("/")
  ) {
    throw new HttpApiEventError(400, "invalid-http-api-event");
  }
  const rawQueryString = value.rawQueryString ?? "";
  if (typeof rawQueryString !== "string" || rawQueryString.includes("#")) {
    throw new HttpApiEventError(400, "invalid-http-api-event");
  }
  const headers = parseHeaders(value.headers);
  const body = value.body;
  if (body !== undefined && typeof body !== "string") {
    throw new HttpApiEventError(400, "invalid-http-api-event");
  }
  const isBase64Encoded = value.isBase64Encoded ?? false;
  if (typeof isBase64Encoded !== "boolean") {
    throw new HttpApiEventError(400, "invalid-http-api-event");
  }
  return {
    rawPath: value.rawPath,
    rawQueryString,
    headers,
    body,
    isBase64Encoded,
    method,
  };
}

function eventToRequest(event: ParsedHttpApiV2Event): Request {
  const url = new URL("https://http-api.internal");
  url.pathname = event.rawPath;
  url.search = event.rawQueryString;

  const headers = new Headers();
  for (const name of ["content-type", "content-encoding", "content-length"]) {
    const value = event.headers[name];
    if (value !== undefined) {
      headers.set(name, value);
    }
  }

  let body: Uint8Array<ArrayBuffer> | undefined;
  if (event.rawPath === NODE_EVENT_PATH && event.method === "POST") {
    if (!event.isBase64Encoded || event.body === undefined) {
      throw new HttpApiEventError(400, "binary-body-required");
    }
    body = decodeBoundedBase64(
      event.body,
      MAX_AWS_HTTP_API_REQUEST_BODY_BYTES,
    );
  }

  return new Request(url, {
    method: event.method,
    headers,
    body,
  });
}

function parseHeaders(value: unknown): Readonly<Record<string, string>> {
  if (value === undefined || value === null) {
    return {};
  }
  if (!isRecord(value)) {
    throw new HttpApiEventError(400, "invalid-http-api-event");
  }
  const headers: Record<string, string> = {};
  for (const [name, header] of Object.entries(value)) {
    if (typeof header !== "string") {
      throw new HttpApiEventError(400, "invalid-http-api-event");
    }
    headers[name.toLowerCase()] = header;
  }
  return headers;
}

function decodeBoundedBase64(
  value: string,
  maximumBytes: number,
): Uint8Array<ArrayBuffer> {
  const maximumEncodedLength = 4 * Math.ceil(maximumBytes / 3);
  if (
    value.length > maximumEncodedLength ||
    value.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u
      .test(value)
  ) {
    throw new HttpApiEventError(400, "invalid-base64-body");
  }
  const decoded = Buffer.from(value, "base64");
  if (
    decoded.byteLength > maximumBytes ||
    decoded.toString("base64") !== value
  ) {
    throw new HttpApiEventError(400, "invalid-base64-body");
  }
  return Uint8Array.from(decoded);
}

async function responseToResult(
  response: Response,
): Promise<AwsHttpApiV2Result> {
  const body = await readBoundedResponseBody(
    response.body,
    MAX_AWS_HTTP_API_RESPONSE_BODY_BYTES,
  );
  const headers: Record<string, string> = {};
  for (const name of ["cache-control", "content-type", "allow"]) {
    const value = response.headers.get(name);
    if (value !== null) {
      headers[name] = value;
    }
  }
  return {
    statusCode: response.status,
    headers,
    body: Buffer.from(body).toString("base64"),
    isBase64Encoded: true,
  };
}

async function readBoundedResponseBody(
  body: ReadableStream<Uint8Array> | null,
  maximumBytes: number,
): Promise<Uint8Array> {
  if (body === null) {
    return new Uint8Array();
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
        await reader.cancel("response exceeds AWS buffered payload budget");
        throw new HttpApiEventError(502, "response-too-large");
      }
      chunks.push(result.value);
      total += result.value.byteLength;
    }
  } finally {
    reader.releaseLock();
  }
  const output = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output;
}

function errorResult(statusCode: number, code: string): AwsHttpApiV2Result {
  return {
    statusCode,
    headers: {
      "cache-control": "no-store",
      "content-type": "text/plain; charset=utf-8",
    },
    body: Buffer.from(code).toString("base64"),
    isBase64Encoded: true,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
