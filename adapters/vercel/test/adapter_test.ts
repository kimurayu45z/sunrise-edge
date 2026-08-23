import { deepStrictEqual, equal } from "node:assert/strict";
import {
  LIVENESS_PATH,
  NODE_EVENT_MEDIA_TYPE,
  NODE_EVENT_PATH,
  NODE_RESULT_MEDIA_TYPE,
} from "../../shared/web-ingress.ts";
import { createVercelHandler, MAX_VERCEL_REQUEST_BODY_BYTES } from "../src/adapter.ts";

const NODE_CORE_URL = "https://node.internal.example/v1/events";

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

Deno.test("Vercel ingress answers liveness without invoking node core", async () => {
  let calls = 0;
  const handler = createVercelHandler({
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

Deno.test("Vercel ingress uses the shared authenticated transport", async () => {
  const body = new Uint8Array([0x53, 0x4e, 0x52, 0x45]);
  let forwarded: Request | undefined;
  const handler = createVercelHandler({
    nodeCoreUrl: NODE_CORE_URL,
    bearerToken: "test-token",
    fetch: (request) => {
      forwarded = request;
      return Promise.resolve(
        new Response(body, {
          headers: { "content-type": NODE_RESULT_MEDIA_TYPE },
        }),
      );
    },
  });

  const response = await handler(eventRequest(body));
  equal(response.status, 200);
  equal(forwarded?.url, NODE_CORE_URL);
  equal(forwarded?.headers.get("authorization"), "Bearer test-token");
  equal(forwarded?.redirect, "error");
  deepStrictEqual(new Uint8Array(await forwarded?.arrayBuffer()), body);
});

Deno.test("Vercel ingress rejects above its conservative platform budget", async () => {
  let calls = 0;
  const handler = createVercelHandler({
    nodeCoreUrl: NODE_CORE_URL,
    bearerToken: "test-token",
    fetch: () => {
      calls += 1;
      return Promise.reject(new Error("must not be called"));
    },
  });

  const response = await handler(
    eventRequest(new Uint8Array([1]), {
      "content-length": String(MAX_VERCEL_REQUEST_BODY_BYTES + 1),
    }),
  );
  equal(response.status, 413);
  equal(await response.text(), "body-too-large");
  equal(calls, 0);
});

Deno.test("Vercel ingress retains exact shared media validation", async () => {
  const handler = createVercelHandler({
    nodeCoreUrl: NODE_CORE_URL,
    bearerToken: "test-token",
    fetch: () => Promise.reject(new Error("must not be called")),
  });

  const response = await handler(
    eventRequest(new Uint8Array([1]), {
      "content-type": `${NODE_EVENT_MEDIA_TYPE}; version=2`,
    }),
  );
  equal(response.status, 415);
  equal(await response.text(), "unsupported-content-type");
});
