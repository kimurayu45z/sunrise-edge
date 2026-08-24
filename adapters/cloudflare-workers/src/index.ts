import { handleWebRequest } from "../../shared/web-ingress";

export {
  LIVENESS_PATH,
  MAX_HTTP_EVENT_BODY_BYTES,
  NODE_EVENT_MEDIA_TYPE,
  NODE_EVENT_PATH,
  NODE_RESULT_MEDIA_TYPE,
  readBoundedBody,
} from "../../shared/web-ingress";

export function handleRequest(request: Request, env: Env): Promise<Response> {
  return handleWebRequest(request, env.NODE_CORE);
}

export default {
  fetch(request: Request, env: Env): Promise<Response> {
    return handleRequest(request, env);
  },
} satisfies ExportedHandler<Env>;
