import { env } from "cloudflare:workers";
import { describe, expect, it, vi } from "vitest";
import { handleWebRequest } from "../../shared/web-ingress";
import {
  LIVENESS_PATH,
  MAX_HTTP_EVENT_BODY_BYTES,
  NODE_EVENT_MEDIA_TYPE,
  NODE_EVENT_PATH,
  NODE_RESULT_MEDIA_TYPE,
  handleRequest,
  readBoundedBody,
} from "../src/index";

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

describe("Cloudflare ingress", () => {
  it("answers liveness without invoking node core", async () => {
    const response = await handleRequest(
      new Request(`https://edge.example${LIVENESS_PATH}`),
      env,
    );

    expect(response.status).toBe(204);
    expect(response.headers.get("cache-control")).toBe("no-store");
  });

  it("forwards a bounded canonical body through the service binding", async () => {
    const body = new Uint8Array([0x53, 0x4e, 0x52, 0x45]);
    const response = await handleRequest(eventRequest(body), env);

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe(NODE_RESULT_MEDIA_TYPE);
    expect(new Uint8Array(await response.arrayBuffer())).toEqual(body);
  });

  it("rejects a success response outside the canonical result contract", async () => {
    const response = await handleRequest(
      eventRequest(new Uint8Array([0xfe])),
      env,
    );

    expect(response.status).toBe(502);
    expect(await response.text()).toBe("invalid-node-core-response");
  });

  it("rejects methods, media parameters, and content encoding", async () => {
    const method = await handleRequest(
      new Request(`https://edge.example${NODE_EVENT_PATH}`, { method: "GET" }),
      env,
    );
    expect(method.status).toBe(405);
    expect(method.headers.get("allow")).toBe("POST");

    const media = await handleRequest(
      eventRequest(new Uint8Array([1]), {
        "content-type": `${NODE_EVENT_MEDIA_TYPE}; version=2`,
      }),
      env,
    );
    expect(media.status).toBe(415);

    const encoding = await handleRequest(
      eventRequest(new Uint8Array([1]), { "content-encoding": "gzip" }),
      env,
    );
    expect(encoding.status).toBe(415);
  });

  it("rejects declared and streamed bodies above the fixed limit", async () => {
    const declared = await handleRequest(
      eventRequest(new Uint8Array([1]), {
        "content-length": String(MAX_HTTP_EVENT_BODY_BYTES + 1),
      }),
      env,
    );
    expect(declared.status).toBe(413);

    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array([1, 2]));
        controller.close();
      },
    });
    await expect(readBoundedBody(stream, 1)).rejects.toMatchObject({
      status: 413,
      code: "body-too-large",
    });
  });

  it("allows a provider to narrow but never raise the shared body limit", async () => {
    const fetch = vi.fn<Env["NODE_CORE"]["fetch"]>();
    const narrowed = await handleWebRequest(
      eventRequest(new Uint8Array([1, 2]), { "content-length": "2" }),
      { fetch },
      { maximumRequestBodyBytes: 1 },
    );
    expect(narrowed.status).toBe(413);
    expect(fetch).not.toHaveBeenCalled();

    await expect(
      handleWebRequest(eventRequest(new Uint8Array([1])), { fetch }, {
        maximumRequestBodyBytes: MAX_HTTP_EVENT_BODY_BYTES + 1,
      }),
    ).rejects.toThrow("maximumRequestBodyBytes");
  });

  it("fails closed when the node-core service binding throws", async () => {
    const response = await handleRequest(
      eventRequest(new Uint8Array([0xff])),
      env,
    );

    expect(response.status).toBe(502);
    expect(await response.text()).toBe("node-core-failure");
  });
});
