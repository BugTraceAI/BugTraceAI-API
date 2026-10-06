# BugTraceAI-API installation

## Universal Launcher (recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/BugTraceAI/BugTraceAI-Launcher/main/install.sh | bash
```

Choose `api` for the independent API-target scanner, `web` for WEB with both
scanning engines, or `full` to include the CLI terminal workspace. In this
checkout, `./install.sh` or bare `./setup.sh` opens the same menu with `api`
suggested (Launcher 3.3.14+). Older Launcher versions are rejected before
installation. The suggestion does not install automatically.

The Launcher prepares Docker, selects ports, configures the shared network and
checks REST/MCP readiness. Provider credentials are optional during setup;
press Enter at the key prompt to add them later in local configuration before
AI-powered analysis. CLI web-scanning API/MCP is a separate engine.

## Direct installation in this checkout

Requirements: Docker Compose v2, available REST/MCP ports and network access
for downloading the image's external tools. The current Dockerfile packages
Linux amd64 tool binaries; native ARM images are not provided by this setup.

```bash
# Create configuration only for a fresh installation; preserve an existing .env.
cp .env.example .env
chmod 600 .env
# Review API_PORT=8005, MCP_PORT=8004 and any provider settings.
./scripts/install-runtime.sh
```

Use your configured REST port if you change 8005. MCP is Streamable HTTP at
`http://localhost:8004/mcp` by default. Provider configuration is optional for
AI enrichment; provider keys remain in local configuration. Starting the
services does not launch a target scan. The direct backend validates Compose,
builds/starts the service, checks REST health/docs and initializes MCP before
reporting success. It preserves `.env`, `docker-compose.yml`, provider settings
and reports; missing configuration fails with an actionable message.

The Launcher is the only guided installer. Legacy `./setup.sh --standalone`
and `./install.sh --standalone` delegate to this same runtime backend. There
is no separate component wizard, and no automatic configuration rewrite.

For direct service management, use `./setup.sh status`, `start`, `stop`,
`restart` or `logs`. For a Launcher-managed installation, use the Launcher's
equivalent commands so all selected products are managed together.
`./setup.sh` is a small compatibility alias for the Launcher and service commands;
the service implementation is in `scripts/service.sh`. `start`/`rebuild` use the
same checked runtime backend. `stop` preserves the containers. Explicit
`uninstall --yes` removes the service but keeps configuration, reports and volumes.

See the [AI coding-agent prompt](README.md#install-with-your-ai-coding-agent),
provider configuration and endpoint reference in [README.md](README.md).

## Updates and compatible versions

For Launcher-managed installations, use Launcher 3.3.14+ and review
`./launcher.sh update --plan` before `./launcher.sh update`. The visual menu also
has **Update installation**. Source tags come from one compatible release
manifest; preparation finishes before activation, and saved settings/data remain
in place. Use `./launcher.sh update --recover` for an interrupted activation.

See the [release and recovery guide](https://github.com/BugTraceAI/BugTraceAI-Launcher/blob/main/RELEASES.md).
Direct component checkouts keep their explicit runtime backend. Choose tagged
versions deliberately, retain local configuration and data, and rerun that
backend; a development checkout is not silently moved to a public release.
