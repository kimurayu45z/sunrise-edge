import { deepStrictEqual, equal } from "node:assert/strict";
import {
  LIVENESS_PATH,
  NODE_EVENT_MEDIA_TYPE,
  NODE_EVENT_PATH,
  NODE_RESULT_MEDIA_TYPE,
} from "../../shared/web-ingress.ts";
import { createSupabaseHandler, SUPABASE_FUNCTION_NAME } from "../src/adapter.ts";

const NODE_CORE_URL = "https://node.internal.example/v1/events";
const FUNCTION_PREFIX = `/${SUPABASE_FUNCTION_NAME}`;

function functionRequest(
  path: string,
  body?: BodyInit,
  headers?: HeadersInit,
): Request {
  return new Request(`https://project.supabase.co${FUNCTION_PREFIX}${path}`, {
    method: body === undefined ? "GET" : "POST",
    headers: body === undefined
      ? headers
      : { "content-type": NODE_EVENT_MEDIA_TYPE, ...headers },
    body,
  });
}

Deno.test("Supabase ingress normalizes prefixed liveness without forwarding", async () => {
  let calls = 0;
  const handler = createSupabaseHandler({
    nodeCoreUrl: NODE_CORE_URL,
    bearerToken: "test-token",
    fetch: () => {
      calls += 1;
      return Promise.reject(new Error("must not be called"));
    },
  });

  const response = await handler(functionRequest(LIVENESS_PATH));
  equal(response.status, 204);
  equal(response.headers.get("cache-control"), "no-store");
  equal(calls, 0);
});

Deno.test("Supabase ingress forwards prefixed events through shared auth", async () => {
  const body = new Uint8Array([0x53, 0x4e, 0x52, 0x45]);
  let forwarded: Request | undefined;
  const handler = createSupabaseHandler({
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

  const response = await handler(functionRequest(NODE_EVENT_PATH, body));
  equal(response.status, 200);
  equal(forwarded?.url, NODE_CORE_URL);
  equal(forwarded?.headers.get("authorization"), "Bearer test-token");
  deepStrictEqual(new Uint8Array(await forwarded?.arrayBuffer()), body);
});

Deno.test("Supabase ingress normalizes only the two exact contract paths", async () => {
  const handler = createSupabaseHandler({
    nodeCoreUrl: NODE_CORE_URL,
    bearerToken: "test-token",
    fetch: () => Promise.reject(new Error("must not be called")),
  });

  for (
    const path of [
      `${NODE_EVENT_PATH}/extra`,
      `/other${NODE_EVENT_PATH}`,
      `${LIVENESS_PATH}/`,
    ]
  ) {
    const response = await handler(functionRequest(path));
    equal(response.status, 404);
    equal(await response.text(), "not-found");
  }
});

Deno.test("Supabase ingress retains exact shared media validation", async () => {
  const handler = createSupabaseHandler({
    nodeCoreUrl: NODE_CORE_URL,
    bearerToken: "test-token",
    fetch: () => Promise.reject(new Error("must not be called")),
  });

  const response = await handler(
    functionRequest(NODE_EVENT_PATH, new Uint8Array([1]), {
      "content-type": `${NODE_EVENT_MEDIA_TYPE}; version=2`,
    }),
  );
  equal(response.status, 415);
  equal(await response.text(), "unsupported-content-type");
});
