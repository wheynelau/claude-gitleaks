# claude-gitleaks

A proxy server for the Anthropic API that detects and redacts leaked API keys and secrets from requests.

## Features

- Scans all requests for leaked secrets using gitleaks
- Redacts detected secrets or rejects requests entirely
- Includes a `/scan` endpoint for checking text without proxying
- OpenTelemetry instrumentation for distributed tracing
- Structured JSON logging
- Custom gitleaks configuration that extends the default rules with additional patterns for passwords, usernames, and API keys

## Usage

```bash
./claude-gitleaks [flags]
```
### Docker

There are docker images provided in the repository

```
docker pull ghcr.io/wheynelau/claude-gitleaks:latest
```

### Compose

The compose file provided is for building and not using the remotely available container

```
docker compose up -d --build
```

If you would like to use the remote image, its a quick change from `build: .` to `image: ghcr.io/wheynelau/claude-gitleaks:latest`. 

_Note: The docker compose references a .gitleaks.toml file at the root_

### Claude code side

Then in another terminal:
```bash
# 8000 is the default
export ANTHROPIC_BASE_URL="http://localhost:8000"
claude
```
## How this works

This is just a simple proxy that reads every request from claude code, checks for sensitive keys using `gitleaks`, then replaces it with `<REDACTED_KEY>`. However, note that its not 100%, and its best to couple this with other best practices, like hooks or fake keys. Where this may shine is when `claude` does things like reading encrypted secrets, like if you have your secrets in a remote and for some reason `claude` can run things like `sops` or `aws secretsmanager`. 

Read more about gitleaks: https://github.com/gitleaks/gitleaks

## Issues

- Due to the way the string replaces, edit files never work. Because they require the full text for replacement.

For example:
```
SECRET_KEY=abcdefg
SECRET_KEY2=qwerty
```
> Instruction: Add a new line of secret after SECRET_KEY2 or add a line in between  
> You will get multiple failed edits from CC

- In `scanner.go`, if tool use returns documents, images or urls, it does not scan them. This can be easily implemented but it depends on use cases. An internal MCP with private documents may make sense, but this tool only scans keys. 

- The gitleaks provided here may be too sensitive, due to the low entropy. Users should adjust the entropy and regex accordingly. 

## Configuration

By default, gitleaks checks for various patterns. The current repo has a sample `.gitleaks.toml`, which contains a password checker as well. Your own rules can be added. 

To use a custom configuration, pass the `-config` flag with a path to a gitleaks TOML file.

### Flags

- `-port int` - Port to run the proxy on (default: 8000)
- `-host string` - Host to bind to (empty = all interfaces)
- `-reject` - Reject requests with detected leaks instead of redacting
- `-config string` - Path to custom gitleaks config file (uses built-in config if not specified)
- `-debug` - Enable debug logging

### Environment Variables

- `ANTHROPIC_BASE_URL` - Upstream Anthropic API endpoint (default: https://api.anthropic.com)
- `OTEL_EXPORTER_OTLP_ENDPOINT` - OpenTelemetry collector endpoint (default: http://localhost:4318)
- `OTEL_SERVICE_NAME` - Service name for OpenTelemetry traces (default: claude-gitleaks)


## TODO

- Ideally, having a HTTPS_PROXY would be better, so that the `ANTHROPIC_BASE_URL` can be set from `claude` rather than setting it on the proxy. 


