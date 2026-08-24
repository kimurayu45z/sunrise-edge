import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        serviceBindings: {
          NODE_CORE: async (request: Request): Promise<Response> => {
            const body = new Uint8Array(await request.arrayBuffer());
            if (body[0] === 0xff) {
              throw new Error("simulated node-core outage");
            }
            if (body[0] === 0xfe) {
              return Response.json({ error: "invalid mock response" });
            }
            return new Response(body, {
              status: 200,
              headers: { "content-type": "application/vnd.sunrise-edge.node-result" },
            });
          },
        },
      },
    }),
  ],
});
