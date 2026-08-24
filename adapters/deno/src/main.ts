import { createDenoHandler } from "./adapter.ts";

const handler = createDenoHandler({
  nodeCoreUrl: requiredEnvironmentVariable("SUNRISE_NODE_CORE_URL"),
  bearerToken: requiredEnvironmentVariable("SUNRISE_NODE_CORE_BEARER_TOKEN"),
  timeoutMilliseconds: Number(
    Deno.env.get("SUNRISE_NODE_CORE_TIMEOUT_MS") ?? "5000",
  ),
});

function requiredEnvironmentVariable(name: string): string {
  const value = Deno.env.get(name);
  if (value === undefined) {
    throw new TypeError(`${name} is required`);
  }
  return value;
}

export default {
  fetch(request: Request): Promise<Response> {
    return handler(request);
  },
} satisfies Deno.ServeDefaultExport;
