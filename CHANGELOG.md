# Changelog

All notable changes to BugTraceAI-API are documented in this file.

## [1.4.11-beta] - 2026-10-05

### Changed
- Require BugTraceAI Launcher 3.3.14 or newer from the universal component entry point, matching the version that fixes combined WEB/API Docker networking.
- Align API installation and AI-agent instructions with the supported Launcher minimum.

## [1.4.10-beta] - 2026-10-05

### Fixed
- Pin the API Compose service to linux/amd64 so ARM hosts build and run the same architecture as the bundled Kiterunner, x8 and VulnAPI tools.
- Scope DOCKER_DEFAULT_PLATFORM to the API runtime so a conflicting caller default does not reject its Compose build.
- Synchronize the Docker image version label with the current API release.

## [1.4.9-beta] - 2026-10-05

### Fixed
- Keep the standalone Launcher bootstrap compatible with the Bash 3.2 regex parser used by macOS.
