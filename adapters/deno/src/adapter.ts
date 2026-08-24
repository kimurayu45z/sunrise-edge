import {
  type AuthenticatedNodeCoreConfig,
  createAuthenticatedNodeCoreFetcher,
  type WebFetch,
} from "../../shared/authenticated-node-core.ts";
import { handleWebRequest } from "../../shared/web-ingress.ts";

export type DenoFetch = WebFetch;
export type DenoIngressConfig = AuthenticatedNodeCoreConfig;

/** Builds an immutable Deno handler around an authenticated node-core client. */
export function createDenoHandler(
  config: DenoIngressConfig,
): (request: Request) => Promise<Response> {
  const nodeCore = createAuthenticatedNodeCoreFetcher(config);
  return (request) => handleWebRequest(request, nodeCore);
}
