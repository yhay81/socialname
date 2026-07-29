import { Container, getContainer } from "@cloudflare/containers";

interface Env {
  CANARY_RUNNER: DurableObjectNamespace<CanaryRunnerContainer>;
  REPORTS: R2Bucket;
  CANARY_REGION: string;
  CANARY_SITES: string;
}

// Each acceptance window needs three runs per region over at least 24 hours,
// so the cron fires every eight hours and a run is deliberately small: ten
// bounded requests per site against reviewed controls.
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
};

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
