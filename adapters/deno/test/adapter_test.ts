import { deepStrictEqual, equal, throws } from "node:assert/strict";
import {
  requestFromConformanceFixture,
  WEB_INGRESS_CONFORMANCE_FIXTURES,
} from "../../shared/conformance-fixtures.ts";
import {
  LIVENESS_PATH,
  NODE_EVENT_MEDIA_TYPE,
  NODE_EVENT_PATH,
  NODE_RESULT_MEDIA_TYPE,
} from "../../shared/web-ingress.ts";
import { createDenoHandler } from "../src/adapter.ts";

const NODE_CORE_URL = "https://node.internal.example/v1/events";

for (const fixture of WEB_INGRESS_CONFORMANCE_FIXTURES) {
  Deno.test(`Deno matches shared fixture: ${fixture.name}`, async () => {
    const handler = createDenoHandler({
      nodeCoreUrl: NODE_CORE_URL,
      bearerToken: "test-token",
      fetch: () => Promise.reject(new Error("must not be called")),
    });
    const response = await handler(
      requestFromConformanceFixture("https://edge.example", fixture),
    );
    equal(response.status, fixture.expectedStatus);
    equal(response.headers.get("cache-control"), "no-store");
    equal(response.headers.get("allow"), fixture.expectedAllow);
    if (fixture.expectedBody === null) {
      equal(response.body, null);
    } else {
      equal(await response.text(), fixture.expectedBody);
    }
  });
}

function eventRequest(body: BodyInit, headers?: HeadersInit): Request {
  return new Request(`https://edge.example${NODE_EVENT_PATH}`, {
    method: "POST",
    headers: {
      "content-type": NODE_EVENT_MEDIA_TYPE,
      ...headers,
    },
    body,
  });
}

Deno.test("Deno ingress answers liveness without invoking node core", async () => {
  let calls = 0;
  const handler = createDenoHandler({
    nodeCoreUrl: NODE_CORE_URL,
    bearerToken: "test-token",
    fetch: () => {
      calls += 1;
      return Promise.reject(new Error("must not be called"));
    },
  });

  const response = await handler(
    new Request(`https://edge.example${LIVENESS_PATH}`),
  );
  equal(response.status, 204);
  equal(response.headers.get("cache-control"), "no-store");
  equal(calls, 0);
});

Deno.test("Deno ingress authenticates an exact bounded node-core request", async () => {
  const body = new Uint8Array([0x53, 0x4e, 0x52, 0x45]);
  let forwarded: Request | undefined;
  const handler = createDenoHandler({
    nodeCoreUrl: NODE_CORE_URL,
    bearerToken: "test-token",
    timeoutMilliseconds: 1_000,
    fetch: (request) => {
      forwarded = request;
      return Promise.resolve(
        new Response(body, {
          status: 200,
          headers: { "content-type": NODE_RESULT_MEDIA_TYPE },
        }),
      );
    },
  });

  const response = await handler(eventRequest(body));
  equal(response.status, 200);
  equal(forwarded?.url, NODE_CORE_URL);
  equal(forwarded?.method, "POST");
  equal(forwarded?.headers.get("authorization"), "Bearer test-token");
  equal(forwarded?.headers.get("content-type"), NODE_EVENT_MEDIA_TYPE);
  equal(forwarded?.headers.get("cache-control"), "no-store");
  equal(forwarded?.redirect, "error");
  deepStrictEqual(
    new Uint8Array(await forwarded?.arrayBuffer()),
    body,
  );
});

Deno.test("Deno ingress keeps shared media and encoding rejection", async () => {
  const handler = createDenoHandler({
    nodeCoreUrl: NODE_CORE_URL,
    bearerToken: "test-token",
    fetch: () => Promise.reject(new Error("must not be called")),
  });

  const media = await handler(
    eventRequest(new Uint8Array([1]), {
      "content-type": `${NODE_EVENT_MEDIA_TYPE}; version=2`,
    }),
  );
  equal(media.status, 415);

  const encoding = await handler(
    eventRequest(new Uint8Array([1]), { "content-encoding": "gzip" }),
  );
  equal(encoding.status, 415);
});

Deno.test("Deno ingress fails closed when authenticated fetch fails", async () => {
  const handler = createDenoHandler({
    nodeCoreUrl: NODE_CORE_URL,
    bearerToken: "test-token",
    fetch: () => Promise.reject(new DOMException("timed out", "TimeoutError")),
  });

  const originalError = console.error;
  console.error = () => {};
  try {
    const response = await handler(eventRequest(new Uint8Array([1])));
    equal(response.status, 503);
    equal(await response.text(), "node-core-unavailable");
  } finally {
    console.error = originalError;
  }
});

Deno.test("Deno ingress rejects unsafe endpoint and secret configuration", () => {
  const base = { bearerToken: "test-token" };
  for (
    const nodeCoreUrl of [
      "http://node.example/v1/events",
      "https://user:pass@node.example/v1/events",
      "https://node.example/v1/events?debug=true",
      "https://node.example/other",
    ]
  ) {
    throws(() => createDenoHandler({ ...base, nodeCoreUrl }), TypeError);
  }

  throws(
    () =>
      createDenoHandler({
        nodeCoreUrl: NODE_CORE_URL,
        bearerToken: " token ",
      }),
    TypeError,
  );
  throws(
    () =>
      createDenoHandler({
        nodeCoreUrl: NODE_CORE_URL,
        bearerToken: "test-token",
        timeoutMilliseconds: 30_001,
      }),
    TypeError,
  );
});

Deno.test("Deno ingress rejects a non-canonical downstream success", async () => {
  const handler = createDenoHandler({
    nodeCoreUrl: NODE_CORE_URL,
    bearerToken: "test-token",
    fetch: () => Promise.resolve(new Response(new Uint8Array([1]))),
  });

  const response = await handler(eventRequest(new Uint8Array([1])));
  equal(response.status, 502);
  equal(await response.text(), "invalid-node-core-response");
});
