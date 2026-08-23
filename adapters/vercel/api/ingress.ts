import process from "node:process";
import { createVercelHandler } from "../src/adapter.ts";

const handler = createVercelHandler({
  nodeCoreUrl: requiredEnvironmentVariable("SUNRISE_NODE_CORE_URL"),
  bearerToken: requiredEnvironmentVariable("SUNRISE_NODE_CORE_BEARER_TOKEN"),
  timeoutMilliseconds: Number(
    process.env.SUNRISE_NODE_CORE_TIMEOUT_MS ?? "5000",
  ),
});

function requiredEnvironmentVariable(name: string): string {
  const value = process.env[name];
  if (value === undefined) {
    throw new TypeError(`${name} is required`);
  }
  return value;
}

export default {
  fetch(request: Request): Promise<Response> {
    return handler(request);
  },
};
