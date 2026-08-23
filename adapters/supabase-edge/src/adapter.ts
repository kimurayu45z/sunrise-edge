import {
  type AuthenticatedNodeCoreConfig,
  createAuthenticatedNodeCoreFetcher,
} from "../../shared/authenticated-node-core.ts";
import {
  handleWebRequest,
  LIVENESS_PATH,
  NODE_EVENT_PATH,
} from "../../shared/web-ingress.ts";

export const SUPABASE_FUNCTION_NAME = "sunrise-edge";
const SUPABASE_FUNCTION_PREFIX = `/${SUPABASE_FUNCTION_NAME}`;

export type SupabaseIngressConfig = AuthenticatedNodeCoreConfig;

/** Builds an immutable Supabase Edge handler around the shared Web contract. */
export function createSupabaseHandler(
  config: SupabaseIngressConfig,
): (request: Request) => Promise<Response> {
  const nodeCore = createAuthenticatedNodeCoreFetcher(config);
  return (request) => handleWebRequest(normalizeFunctionPath(request), nodeCore);
}

function normalizeFunctionPath(request: Request): Request {
  const url = new URL(request.url);
  for (const path of [NODE_EVENT_PATH, LIVENESS_PATH]) {
    if (url.pathname === `${SUPABASE_FUNCTION_PREFIX}${path}`) {
      url.pathname = path;
      return new Request(url, request);
    }
  }
  return request;
}
