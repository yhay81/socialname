# Installing SocialName

Status: **Unsigned artifacts; local surfaces usable; the managed service is
not hosted yet, and self-hosting is not a product surface**

SocialName has three surfaces. Read the honest capability summary first,
because the two local ones do useful work today and the third ships with the
managed service, which is not hosted yet.

| Surface | Who it is for | Works without any account or server | Today's limit |
| --- | --- | --- | --- |
| Desktop application | Anyone | Yes | Ten representative sites; installers are unsigned |
| Command line | Terminal users | Yes | Same ten sites; `--allow-disabled` needed for live probes |
| Monitoring console (web) | Operators and teams | No | Part of the managed service, which is not hosted yet |

Two facts shape everything below and are not marketing caveats:

- **All ten site rules are discovery-only.** No rule has passed the live
  canary gate, so nothing is promoted. Local searches still run and return
  real evidence; the CLI just requires you to acknowledge that with
  `--allow-disabled`, and cached or managed reuse stays disabled.
- **Nothing here is code-signed.** The project holds no Apple Developer
  identity and no Windows signing certificate, so Gatekeeper and SmartScreen
  will warn. Every warning you see below is expected, and the workaround is
  documented rather than hidden.

## Desktop application

Download the installer for your platform from the
[latest release](https://github.com/yhay81/socialname/releases/latest), then
verify it against `SHA256SUMS.txt` from the same release before installing.

```bash
# macOS or Linux
shasum -a 256 -c SHA256SUMS.txt --ignore-missing
```

```powershell
# Windows
(Get-FileHash .\SocialName_0.2.0_x64-setup.exe -Algorithm SHA256).Hash
# compare with the matching line in SHA256SUMS.txt
```

### Windows

Run `SocialName_<version>_x64-setup.exe`. SmartScreen shows **"Windows
protected your PC"** because the installer is unsigned. Choose **More info →
Run anyway** only after the checksum matches.

### macOS

Open `SocialName_<version>_universal.dmg` and drag the application to
`/Applications`. Because the bundle is neither signed nor notarized, the first
launch is blocked. Open it once with **Control-click → Open**, or clear the
quarantine attribute yourself:

```bash
xattr -dr com.apple.quarantine /Applications/SocialName.app
```

Do that only when the checksum matched. Signed and notarized builds require an
Apple Developer account, which is an external gate this repository does not
hold.

### Linux

Three artifacts are published. Install the package your distribution uses, or
run the portable AppImage:

```bash
sudo apt install ./SocialName_<version>_amd64.deb
sudo dnf install ./SocialName-<version>-1.x86_64.rpm
chmod +x SocialName_<version>_amd64.AppImage && ./SocialName_<version>_amd64.AppImage
```

The AppImage is much larger than the packages because it carries its own
WebKit runtime instead of using the system one.

### What the desktop application does

It searches the ten representative sites locally, streams results as they
arrive, and shows the evidence class, matcher outcome, timing, and rule
identity behind every verdict. The default is local execution with
`sync=never`: no account, no telemetry, and no request to any SocialName
service. Remote and cached-first modes exist but need a server you point it
at.

## Command line

Archives are published for six targets: Windows, macOS, and Linux on both
x86-64 and arm64.

### Homebrew

```bash
brew install yhay81/tap/socialname            # command line
brew install --cask yhay81/tap/socialname-desktop
```

The tap is updated by the release workflow when the tap credential is
configured; until then use the prebuilt binary or the installer.

### WinGet

```powershell
winget install yhay81.SocialName
```

The release workflow renders the WinGet manifests and attaches them to the
release. Submitting them to `microsoft/winget-pkgs` is a separate
authenticated pull request, so this command works only after that submission
is merged.

### Prebuilt binary

```bash
curl -fsSL https://raw.githubusercontent.com/yhay81/socialname/main/scripts/install-cli.sh | sh
```

```powershell
irm https://raw.githubusercontent.com/yhay81/socialname/main/scripts/install-cli.ps1 | iex
```

Both scripts download one release archive plus `SHA256SUMS.txt`, refuse to
install on a checksum mismatch, and unpack the binary and its rule pack under
`~/.socialname` (`%LOCALAPPDATA%\SocialName` on Windows). Neither needs
administrator rights. Read the script before piping it to a shell; that advice
applies to every installer of this shape, including this one.

### From source

```bash
cargo install --git https://github.com/yhay81/socialname socialname-cli --locked
```

The binary is named `socialname`. Installing from source does not place the
site-rule pack anywhere, so pass `--rules-dir` at a checkout of `rules/sites`.

### First searches

The installed layout keeps the rule pack beside the binary, so point
`--rules-dir` at it (`%LOCALAPPDATA%\SocialName\rules\sites` on Windows):

```bash
socialname rules list --rules-dir ~/.socialname/rules/sites
socialname search octocat --site github \
  --rules-dir ~/.socialname/rules/sites --allow-disabled
socialname search octocat --site github \
  --rules-dir ~/.socialname/rules/sites --allow-disabled --json
```

Run from inside an unpacked archive, `--rules-dir rules/sites` is enough.

`--allow-disabled` is the explicit acknowledgement that the rule has not
passed its live canary gate. Without it the CLI refuses to probe, which is the
intended fail-closed default rather than a bug.

`pip install socialname` installs the **legacy Python package** from before the
Rust rewrite. It is unrelated to the surfaces on this page.

## Monitoring console (web)

The console is the watch, transition, review, and operational-report surface.
It consumes only `/v1` on its own origin and holds a pasted scoped API key in
page memory alone — never in local storage, never in a cookie. There is no
hosted instance yet: publishing one requires managed deployment credentials, a
domain, and TLS, all of which are external gates recorded in
[`docs/regional-worker-deployment.md`](regional-worker-deployment.md).
Self-hosting is deliberately not a product surface — the managed service
concentrates observations, rule health, and coalescing in one operated place
([decision](decisions-2026-07-28.md)).

Contributors working on the server, worker, or console run the same stack as
a development harness:

```bash
cd deploy
cp .env.example .env      # generate both secrets as the file explains
docker compose up --build
```

That builds the server image with the console bundled, applies the embedded
migrations with a schema-owner credential, and serves
<http://127.0.0.1:8080/console>.

Then create a workspace and an API key to paste into the console:

```bash
docker compose run --rm \
  -e SOCIALNAME_WORKSPACE_SLUG=example \
  -e SOCIALNAME_WORKSPACE_DISPLAY_NAME="Example workspace" \
  -e SOCIALNAME_MEMBERSHIP_SUBJECT=owner \
  -e SOCIALNAME_API_KEY_SCOPES=workspace:read,watch:read,watch:write,operations:read \
  server bootstrap-workspace
```

The command prints the key exactly once.

### What the stack deliberately does not do

It binds to loopback, terminates no TLS, runs no managed worker, and holds no
rule-pack trust root. Watches can therefore be created and reviewed, but no
managed probe executes and no transition or notification is produced, because
promoting a rule requires the live canary evidence gate. Running this stack on
a public address would need TLS termination, a reverse proxy, and the
production security review that Milestone 2's external gate names.

## Serving the console from a local build

Any `socialname-server` process serves the console when
`SOCIALNAME_CONSOLE_DIR` points at a built bundle:

```bash
cd apps/console && npm ci && npm run build && cd ../..
SOCIALNAME_CONSOLE_DIR=apps/console/dist \
SOCIALNAME_SERVER_DATABASE_URL=postgres://... \
SOCIALNAME_SUPPRESSION_HMAC_KEY_HEX=<64 hex characters> \
  cargo run --locked -p socialname-server
```

Without the variable the route does not exist at all. A path that is missing,
is not a directory, or lacks `index.html` is a startup configuration error
rather than a silently disabled console.

## Not yet available

These are distribution gaps, each blocked on an account, a credential, or an
external review rather than on code:

- signed and notarized macOS builds, and a signed Windows installer;
- a merged `microsoft/winget-pkgs` submission, so `winget install` resolves;
- a `HOMEBREW_TAP_TOKEN` secret, so releases update the tap automatically;
- `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` secrets, so the product
  page at <https://socialname.yhay81.com> deploys on every change;
- Scoop and Linux distribution repository packages;
- a `crates.io` release of `socialname-cli`;
- automatic updates for the desktop application;
- a hosted monitoring console.

The Homebrew formula and cask and the three WinGet manifests are generated
from each release by
[`scripts/render-package-manifests.sh`](../scripts/render-package-manifests.sh),
which reads every checksum from the release's own `SHA256SUMS.txt` and fails
rather than emit a manifest with a missing digest or an unsubstituted
placeholder.
