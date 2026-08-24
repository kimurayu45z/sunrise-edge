import {
  type AuthenticatedNodeCoreConfig,
  createAuthenticatedNodeCoreFetcher,
} from "../../shared/authenticated-node-core.ts";
import { handleWebRequest } from "../../shared/web-ingress.ts";

// Vercel documents a 4.5 MB Function payload ceiling. Keep a conservative,
// binary-aligned budget below it and below the shared protocol transport bound.
export const MAX_VERCEL_REQUEST_BODY_BYTES = 4 * 1024 * 1024;

export type VercelIngressConfig = AuthenticatedNodeCoreConfig;

/** Builds an immutable Vercel handler around an authenticated node-core client. */
export function createVercelHandler(
  config: VercelIngressConfig,
): (request: Request) => Promise<Response> {
  const nodeCore = createAuthenticatedNodeCoreFetcher(config);
  return (request) =>
    handleWebRequest(request, nodeCore, {
      maximumRequestBodyBytes: MAX_VERCEL_REQUEST_BODY_BYTES,
    });
}
