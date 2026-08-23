import {
  type AuthenticatedNodeCoreConfig,
  createAuthenticatedNodeCoreFetcher,
} from "../../shared/authenticated-node-core.ts";
import { handleWebRequest } from "../../shared/web-ingress.ts";
import {
  AWS_HTTP_API_INGRESS_OPTIONS,
  type AwsHttpApiV2Result,
  handleAwsHttpApiV2Event,
} from "./http-api-v2.ts";

export type AwsLambdaIngressConfig = AuthenticatedNodeCoreConfig;

/** Builds an immutable API Gateway HTTP API v2 Lambda handler. */
export function createAwsLambdaHandler(
  config: AwsLambdaIngressConfig,
): (event: unknown) => Promise<AwsHttpApiV2Result> {
  const nodeCore = createAuthenticatedNodeCoreFetcher(config);
  const webHandler = (request: Request) =>
    handleWebRequest(request, nodeCore, AWS_HTTP_API_INGRESS_OPTIONS);
  return (event) => handleAwsHttpApiV2Event(event, webHandler);
}
