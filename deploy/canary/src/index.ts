import { Container, getContainer } from "@cloudflare/containers";

interface Env {
  CANARY_RUNNER: DurableObjectNamespace<CanaryRunnerContainer>;
  REPORTS: R2Bucket;
  CANARY_REGION: string;
  CANARY_SITES: string;
  /// Shared secret for the external trigger. Absent means the trigger is
  /// closed, which is the safe state: no request can then start a probe.
  CANARY_TRIGGER_TOKEN?: string;
}

// Each exact 24-hour acceptance window needs three runs per region whose first
// and last completions are at least 18 hours apart. The two-hour cadence
// tolerates several best-effort trigger misses, and every run remains
// deliberately small: ten bounded requests per site against reviewed controls.
const MAX_REQUESTS = "32";
const MAX_CONCURRENCY = "4";
const MAX_ELAPSED_MS = "120000";
const MAX_RESPONSE_BYTES = "16777216";
// The image is inert by default: its entrypoint prints help and exits. The
// container is therefore started under a bounded idle command, and the canary
// itself runs as an explicit exec that must carry --allow-live.
const IDLE_ENTRYPOINT = ["/bin/sleep", "600"];

export class CanaryRunnerContainer extends Container<Env> {
  sleepAfter = "2m";

  async runCanary(site: string, region: string): Promise<CanaryOutcome> {
    const container = this.ctx.container;
    if (!container) {
      throw new Error("container binding is unavailable");
    }
    if (!container.running) {
      container.start({ entrypoint: IDLE_ENTRYPOINT, enableInternet: true });
      await this.waitForIdleProcess();
    }
    const process = await container.exec([
      "/usr/local/bin/socialname",
      "canaries",
      "run",
      "--site",
      site,
      "--region",
      region,
      "--rules-dir",
      "/opt/socialname/rules/sites",
      "--manifests-dir",
      "/opt/socialname/rules/canaries",
      "--max-requests",
      MAX_REQUESTS,
      "--max-concurrency",
      MAX_CONCURRENCY,
      "--max-elapsed-ms",
      MAX_ELAPSED_MS,
      "--max-response-bytes",
      MAX_RESPONSE_BYTES,
      "--allow-live",
      "--json",
    ]);
    const output = await process.output();
    const decoder = new TextDecoder();
    return {
      exitCode: output.exitCode,
      stdout: decoder.decode(output.stdout),
      stderr: decoder.decode(output.stderr),
    };
  }

  // `exec` requires a running container, and `start` does not block until the
  // process exists.
  private async waitForIdleProcess(): Promise<void> {
    for (let attempt = 0; attempt < 30; attempt += 1) {
      if (this.ctx.container?.running) {
        return;
      }
      await scheduler.wait(1000);
    }
    throw new Error("container did not start");
  }
}

interface CanaryOutcome {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export default {
  async scheduled(
    event: ScheduledController,
    env: Env,
    ctx: ExecutionContext,
  ): Promise<void> {
    console.log(`canary cron fired region=${env.CANARY_REGION}`);
    ctx.waitUntil(
      runAllSites(env, new Date(event.scheduledTime)).catch((error: unknown) => {
        console.log(`canary cron failed: ${String(error)}`);
      }),
    );
  },

  /// A second, independent way to start a run.
  ///
  /// Cloudflare's cron is best effort and was observed to skip repeatedly,
  /// including one region that produced nothing for a full day. Acceptance
  /// needs runs near both ends of a day, so missed triggers do not merely
  /// thin the evidence, they make the window impossible. An external
  /// scheduler calling this endpoint fails independently of Cloudflare's,
  /// and either path alone is enough.
  ///
  /// This deliberately reopens an HTTP surface that was previously closed
  /// altogether, so the bar is a shared secret compared in constant time. An
  /// unauthenticated request can never reach the probe path, and with no
  /// token configured the endpoint refuses everything.
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    if (request.method !== "POST") {
      return new Response("method not allowed\n", { status: 405 });
    }
    if (!(await authorized(request, env))) {
      return new Response("unauthorized\n", { status: 401 });
    }
    const startedAt = new Date();
    console.log(`canary trigger accepted region=${env.CANARY_REGION}`);
    ctx.waitUntil(
      runAllSites(env, startedAt).catch((error: unknown) => {
        console.log(`canary trigger failed: ${String(error)}`);
      }),
    );
    return new Response(
      `${JSON.stringify({
        region: env.CANARY_REGION,
        slot: startedAt.toISOString(),
        accepted: true,
      })}\n`,
      { status: 202, headers: { "content-type": "application/json" } },
    );
  },
};

async function authorized(request: Request, env: Env): Promise<boolean> {
  const expected = env.CANARY_TRIGGER_TOKEN;
  if (!expected) {
    return false;
  }
  const header = request.headers.get("authorization") ?? "";
  const prefix = "Bearer ";
  if (!header.startsWith(prefix)) {
    return false;
  }
  const encoder = new TextEncoder();
  const provided = encoder.encode(header.slice(prefix.length));
  const wanted = encoder.encode(expected);
  // timingSafeEqual requires equal lengths, and length alone is not a secret
  // worth protecting here.
  if (provided.byteLength !== wanted.byteLength) {
    return false;
  }
  return crypto.subtle.timingSafeEqual(provided, wanted);
}

/// Reports are keyed by the scheduled slot rather than by the moment a run
/// happened, because the cron fires at fixed hours. That makes every key
/// derivable without listing the bucket, and makes a retry of the same slot
/// replace its own report instead of accumulating near-duplicates.
function reportKey(site: string, region: string, scheduledAt: Date): string {
  const day = scheduledAt.toISOString().slice(0, 10);
  const hour = String(scheduledAt.getUTCHours()).padStart(2, "0");
  return `canary/${site}/${region}/${day}/${hour}.json`;
}

async function runAllSites(env: Env, scheduledAt: Date): Promise<void> {
  const region = env.CANARY_REGION;
  const sites = env.CANARY_SITES.split(",")
    .map((site) => site.trim())
    .filter(Boolean);
  const runner = getContainer(env.CANARY_RUNNER, `canary-${region}`);
  for (const site of sites) {
    const startedAt = new Date().toISOString();
    let outcome: CanaryOutcome;
    try {
      outcome = await runner.runCanary(site, region);
    } catch (error) {
      // A runner failure is an operational fact worth retaining: an absent
      // report and a failed report are different things to an aggregator.
      outcome = {
        exitCode: -1,
        stdout: "",
        stderr: error instanceof Error ? error.message : String(error),
      };
    }
    const key = reportKey(site, region, scheduledAt);
    console.log(
      `canary run site=${site} region=${region} exit=${outcome.exitCode} ` +
        `stdout_bytes=${outcome.stdout.length} key=${key}`,
    );
    await env.REPORTS.put(
      key,
      JSON.stringify({
        site,
        region,
        scheduled_at: scheduledAt.toISOString(),
        started_at: startedAt,
        exit_code: outcome.exitCode,
        report: parseReport(outcome.stdout),
        stderr: outcome.stderr.slice(0, 4096),
      }),
      { httpMetadata: { contentType: "application/json" } },
    );
  }
}

function parseReport(stdout: string): unknown {
  const start = stdout.indexOf("{");
  if (start < 0) {
    return null;
  }
  try {
    return JSON.parse(stdout.slice(start));
  } catch {
    return null;
  }
}
