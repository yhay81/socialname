import { Container, getContainer } from "@cloudflare/containers";

interface Env {
  API_SERVER: DurableObjectNamespace<ApiServerContainer>;
  SOCIALNAME_SERVER_DATABASE_URL?: string;
  SOCIALNAME_SUPPRESSION_HMAC_KEY_HEX?: string;
}

// One singleton container runs the API server image. The server keeps its
// own fail-closed behavior: with the secrets still unset it exits before
// listening instead of serving a half-configured API, so a deployment that
// precedes `wrangler secret put` cannot answer requests.
export class ApiServerContainer extends Container<Env> {
  defaultPort = 8080;
  // Keep scale-to-zero responsive to secret rotation as well as inexpensive:
  // a newly started process receives the current Worker secret values.
  sleepAfter = "1m";

  constructor(ctx: DurableObjectState<{}>, env: Env) {
    super(ctx, env);
    this.envVars = {
      SOCIALNAME_SERVER_BIND: "0.0.0.0:8080",
      SOCIALNAME_SERVER_DATABASE_URL: env.SOCIALNAME_SERVER_DATABASE_URL ?? "",
      SOCIALNAME_SUPPRESSION_HMAC_KEY_HEX:
        env.SOCIALNAME_SUPPRESSION_HMAC_KEY_HEX ?? "",
    };
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    return getContainer(env.API_SERVER).fetch(request);
  },
};
