# Security policy

## Authorized use

BugTraceAI-API is intended exclusively for systems you own or are explicitly authorized to assess. Operators are responsible for defining the scope, permitted methods, test accounts, maintenance windows and data-handling requirements before launching a scan.

`safe` is the default mode. `audit` mode may send `POST`, `PUT`, `PATCH` and `DELETE` requests and can modify target data.

## Supported version

Security fixes are applied to the latest beta release on the active development branch. Older snapshots should be upgraded before reporting a behavior already addressed by a current release.

## Deployment guidance

BugTraceAI-API does not currently provide built-in user authentication, authorization or tenant isolation. Do not expose ports `8004` or `8005` directly to the public Internet.

For remote operation:

1. Place the service on a trusted management network.
2. Restrict source addresses with a host or network firewall.
3. Put TLS and strong authentication in front of both REST and MCP.
4. Limit access to `reports/` and `config/provider_secrets.json`.
5. Rotate provider keys if a host, image or report archive may have been exposed.
6. Review report data-retention requirements because evidence may contain sensitive response excerpts.

The repository excludes `.env` and `config/provider_secrets.json` from both Git and Docker build contexts. Keep custom deployment secrets out of Compose files and shell history where possible.

## Reporting a vulnerability

Do not open a public issue containing credentials, target data, exploit details or unpublished vulnerabilities. Report security problems privately to the BugTraceAI maintainers and include:

- affected version or commit;
- deployment method;
- reproduction steps using a non-sensitive test target;
- expected and observed behavior;
- impact assessment;
- relevant logs with secrets and target data redacted.

Please allow maintainers time to reproduce and correct the issue before public disclosure.

