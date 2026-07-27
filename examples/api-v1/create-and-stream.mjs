import { pathToFileURL } from "node:url";

import { SocialNameApiClient, readStdinJson } from "./client.mjs";

export async function main(environment = process.env) {
  const client = new SocialNameApiClient({
    baseUrl: required(environment, "SOCIALNAME_API_URL"),
    apiKey: required(environment, "SOCIALNAME_API_KEY"),
  });
  const request = await readStdinJson();
  const search = await client.createSearch(
    request,
    environment.SOCIALNAME_IDEMPOTENCY_KEY,
  );
  process.stdout.write(`${JSON.stringify({ resource: search })}\n`);
  await client.streamSearchToTerminal(search.search_id, async (event) => {
    process.stdout.write(`${JSON.stringify({ event })}\n`);
  });
}

function required(environment, name) {
  const value = environment[name];
  if (value === undefined || value === "") {
    throw new Error(`missing_${name.toLowerCase()}`);
  }
  return value;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
