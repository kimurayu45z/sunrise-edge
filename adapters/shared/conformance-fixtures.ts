import {
  LIVENESS_PATH,
  NODE_EVENT_MEDIA_TYPE,
  NODE_EVENT_PATH,
} from "./web-ingress.ts";

export interface WebIngressConformanceFixture {
  readonly name: string;
  readonly path: string;
  readonly method: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: readonly number[] | null;
  readonly expectedStatus: number;
  readonly expectedBody: string | null;
  readonly expectedAllow: string | null;
}

/** Provider-independent fixtures that must complete before node-core dispatch. */
export const WEB_INGRESS_CONFORMANCE_FIXTURES:
  readonly WebIngressConformanceFixture[] = [
    {
      name: "liveness",
      path: LIVENESS_PATH,
      method: "GET",
      headers: {},
      body: null,
      expectedStatus: 204,
      expectedBody: null,
      expectedAllow: null,
    },
    {
      name: "unknown path",
      path: "/not-a-node-route",
      method: "GET",
      headers: {},
      body: null,
      expectedStatus: 404,
      expectedBody: "not-found",
      expectedAllow: null,
    },
    {
      name: "wrong event method",
      path: NODE_EVENT_PATH,
      method: "GET",
      headers: {},
      body: null,
      expectedStatus: 405,
      expectedBody: "method-not-allowed",
      expectedAllow: "POST",
    },
    {
      name: "parameterized media type",
      path: NODE_EVENT_PATH,
      method: "POST",
      headers: {
        "content-type": `${NODE_EVENT_MEDIA_TYPE}; version=2`,
      },
      body: [1],
      expectedStatus: 415,
      expectedBody: "unsupported-content-type",
      expectedAllow: null,
    },
    {
      name: "compressed event body",
      path: NODE_EVENT_PATH,
      method: "POST",
      headers: {
        "content-type": NODE_EVENT_MEDIA_TYPE,
        "content-encoding": "gzip",
      },
      body: [1],
      expectedStatus: 415,
      expectedBody: "unsupported-content-encoding",
      expectedAllow: null,
    },
    {
      name: "non-canonical content length",
      path: NODE_EVENT_PATH,
      method: "POST",
      headers: {
        "content-type": NODE_EVENT_MEDIA_TYPE,
        "content-length": "01",
      },
      body: [1],
      expectedStatus: 400,
      expectedBody: "invalid-content-length",
      expectedAllow: null,
    },
  ];

export function requestFromConformanceFixture(
  origin: string,
  fixture: WebIngressConformanceFixture,
  pathPrefix = "",
): Request {
  return new Request(new URL(`${pathPrefix}${fixture.path}`, origin), {
    method: fixture.method,
    headers: fixture.headers,
    body: fixture.body === null ? null : new Uint8Array(fixture.body),
  });
}
