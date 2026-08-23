import { Buffer } from "node:buffer";
import { deepStrictEqual, equal } from "node:assert/strict";
import {
  LIVENESS_PATH,
  NODE_EVENT_MEDIA_TYPE,
  NODE_EVENT_PATH,
  NODE_RESULT_MEDIA_TYPE,
} from "../../shared/web-ingress.ts";
import { createAwsLambdaHandler } from "../src/adapter.ts";
import {
  MAX_AWS_HTTP_API_REQUEST_BODY_BYTES,
  MAX_AWS_HTTP_API_RESPONSE_BODY_BYTES,
} from "../src/http-api-v2.ts";

const NODE_CORE_URL = "https://node.internal.example/v1/events";

function event(
  rawPath: string,
  method: string,
  body?: Uint8Array,
): Record<string, unknown> {
  return {
    version: "2.0",
    rawPath,
    rawQueryString: "",
    headers: body === undefined ? {} : {
      "content-type": NODE_EVENT_MEDIA_TYPE,
      "content-length": String(body.byteLength),
    },
    requestContext: { http: { method } },
    body: body === undefined ? undefined : Buffer.from(body).toString("base64"),
    isBase64Encoded: body !== undefined,
  };
}

function decodeResultBody(result: { body: string }): Uint8Array {
  return Uint8Array.from(Buffer.from(result.body, "base64"));
}

Deno.test("AWS HTTP API mapper answers liveness without forwarding", async () => {
  let calls = 0;
  const handler = createAwsLambdaHandler({
    nodeCoreUrl: NODE_CORE_URL,
    bearerToken: "test-token",
    fetch: () => {
      calls += 1;
      return Promise.reject(new Error("must not be called"));
    },
  });

  const result = await handler(event(LIVENESS_PATH, "GET"));
  equal(result.statusCode, 204);
  equal(result.headers["cache-control"], "no-store");
  equal(result.isBase64Encoded, true);
  equal(decodeResultBody(result).byteLength, 0);
  equal(calls, 0);
});

Deno.test("AWS HTTP API mapper preserves canonical binary bytes", async () => {
  const body = new Uint8Array([0x53, 0x4e, 0x52, 0x45]);
  let forwarded: Request | undefined;
  const handler = createAwsLambdaHandler({
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

  const result = await handler(event(NODE_EVENT_PATH, "POST", body));
  equal(result.statusCode, 200);
  equal(result.headers["content-type"], NODE_RESULT_MEDIA_TYPE);
  deepStrictEqual(decodeResultBody(result), body);
  equal(forwarded?.headers.get("authorization"), "Bearer test-token");
  deepStrictEqual(new Uint8Array(await forwarded?.arrayBuffer()), body);
});

Deno.test("AWS HTTP API mapper requires version 2 and canonical base64", async () => {
  const handler = createAwsLambdaHandler({
    nodeCoreUrl: NODE_CORE_URL,
    bearerToken: "test-token",
    fetch: () => Promise.reject(new Error("must not be called")),
  });

  const wrongVersion = event(NODE_EVENT_PATH, "POST", new Uint8Array([1]));
  wrongVersion.version = "1.0";
  const versionResult = await handler(wrongVersion);
  equal(versionResult.statusCode, 400);
  equal(
    new TextDecoder().decode(decodeResultBody(versionResult)),
    "invalid-http-api-event",
  );

  const invalidBase64 = event(NODE_EVENT_PATH, "POST", new Uint8Array([1]));
  invalidBase64.body = "AQ";
  const base64Result = await handler(invalidBase64);
  equal(base64Result.statusCode, 400);
  equal(
    new TextDecoder().decode(decodeResultBody(base64Result)),
    "invalid-base64-body",
  );

  const plainBody = event(NODE_EVENT_PATH, "POST", new Uint8Array([1]));
  plainBody.isBase64Encoded = false;
  const plainResult = await handler(plainBody);
  equal(plainResult.statusCode, 400);
  equal(
    new TextDecoder().decode(decodeResultBody(plainResult)),
    "binary-body-required",
  );
});

Deno.test("AWS HTTP API mapper applies the conservative request budget", async () => {
  let calls = 0;
  const handler = createAwsLambdaHandler({
    nodeCoreUrl: NODE_CORE_URL,
    bearerToken: "test-token",
    fetch: () => {
      calls += 1;
      return Promise.reject(new Error("must not be called"));
    },
  });
  const oversized = event(NODE_EVENT_PATH, "POST", new Uint8Array([1]));
  oversized.headers = {
    "content-type": NODE_EVENT_MEDIA_TYPE,
    "content-length": String(MAX_AWS_HTTP_API_REQUEST_BODY_BYTES + 1),
  };

  const result = await handler(oversized);
  equal(result.statusCode, 413);
  equal(new TextDecoder().decode(decodeResultBody(result)), "body-too-large");
  equal(calls, 0);
});

Deno.test("AWS HTTP API mapper sanitizes unknown routes and headers", async () => {
  const handler = createAwsLambdaHandler({
    nodeCoreUrl: NODE_CORE_URL,
    bearerToken: "test-token",
    fetch: () => Promise.reject(new Error("must not be called")),
  });
  const unknown = event("/other", "POST", new Uint8Array([1]));
  unknown.headers = {
    "content-type": NODE_EVENT_MEDIA_TYPE,
    "x-untrusted": "must-not-return",
  };

  const result = await handler(unknown);
  equal(result.statusCode, 404);
  equal(result.headers["x-untrusted"], undefined);
  equal(new TextDecoder().decode(decodeResultBody(result)), "not-found");
});

Deno.test("AWS HTTP API mapper fails closed on a buffered oversized response", async () => {
  const handler = createAwsLambdaHandler({
    nodeCoreUrl: NODE_CORE_URL,
    bearerToken: "test-token",
    fetch: () =>
      Promise.resolve(
        new Response(
          new Uint8Array(MAX_AWS_HTTP_API_RESPONSE_BODY_BYTES + 1),
          { headers: { "content-type": NODE_RESULT_MEDIA_TYPE } },
        ),
      ),
  });

  const result = await handler(
    event(NODE_EVENT_PATH, "POST", new Uint8Array([1])),
  );
  equal(result.statusCode, 502);
  equal(
    new TextDecoder().decode(decodeResultBody(result)),
    "response-too-large",
  );
});
