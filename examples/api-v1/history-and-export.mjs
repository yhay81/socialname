import { pathToFileURL } from "node:url";

import { SocialNameApiClient, readStdinJson } from "./client.mjs";

export async function main(environment = process.env) {
  const client = new SocialNameApiClient({
    baseUrl: required(environment, "SOCIALNAME_API_URL"),
    apiKey: required(environment, "SOCIALNAME_API_KEY"),
  });
  const input = await readStdinJson();
  if (input.action === "history") {
    await emitHistory(client);
  } else if (input.action === "export" && typeof input.search_id === "string") {
    await emitExport(client, input.search_id);
  } else {
    throw new Error("invalid_input");
  }
}

async function emitHistory(client) {
  let after;
  do {
    const page = await client.listSearches({ after });
    process.stdout.write(`${JSON.stringify(page)}\n`);
    after = page.next_cursor ?? undefined;
  } while (after !== undefined);
}

async function emitExport(client, searchId) {
  let after;
  do {
    const page = await client.exportSearch(searchId, { after });
    process.stdout.write(`${JSON.stringify(page)}\n`);
    after = page.next_cursor ?? undefined;
  } while (after !== undefined);
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
