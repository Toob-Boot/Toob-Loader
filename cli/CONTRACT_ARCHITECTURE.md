# Toob Ecosystem Contracts & Ports Architecture

This document serves as the architectural single source of truth for how system boundaries (Contracts/Ports) are defined, verified, and enforced across the Toob ecosystem.

## 1. The `ports.go` Philosophy

In both the CLI and the Orchestrator, we use a dedicated `ports.go` file. This file acts as an **Interface Contract Registry**. It is the absolute source of truth for any data structure that crosses a system boundary (e.g., JSON Webhooks, Docker Labels, HTTP API Requests/Responses).

### The Golden Rules of Tagging
Every exported field inside a port struct **must** contain a `port` struct tag.
- `port:"required"`: The field is strictly required by the contract. Adding or changing a required field, or removing *any* field, is considered a **BREAKING CHANGE**.
- `port:"optional"`: The field is optional. Adding a new optional field is considered a **NON-BREAKING CHANGE**.

---

## 2. Toob-CLI: The SemVer Enforcer Workflow

The `toob-cli` is a distributed binary. Because users might run an older version of the CLI against a newer Compiler Container, we must prevent and detect **Version Skew**.

### Triggers & CI Integration
- **When:** The SemVer Enforcer runs automatically as a GitHub Action (`semver-enforcer.yml`) whenever a Pull Request modifies files in `cli/toob-cli/**`.
- **How it works:** 
  1. The pipeline fetches the `ports.go` from the `HEAD~1` baseline (the state before the PR).
  2. It runs the AST-based diffing tool (`cmd/semver`).
  3. The tool compares the old Abstract Syntax Tree against the new one.

### Enforcement Logic
- **Breaking Changes:** If the AST tool detects a breaking change (e.g., adding a `port:"required"` field, removing a field, changing a type), it forces the pipeline to check if the `ProtocolVersion` constant was manually incremented. **If not, the CI pipeline fails.**
- **Non-Breaking Changes:** Adding a `port:"optional"` field yields a `PATCH` or `MINOR` resolution, which passes without requiring a `ProtocolVersion` bump.

### Local Guards (`assertions_test.go`)
While the AST tool guards the external contract, `assertions_test.go` (run via `go test ./internal/ports/...`) guards the **internal consistency**. It uses Go reflection to ensure that the external `ports.go` structs and the internal implementation structs (e.g., `types.go`) have matching field counts and types, preventing them from silently drifting apart during local development.

---

## 3. Toob-CI Orchestrator: Co-Deployed Parity

The Orchestrator (`toob-ci`) has a fundamentally different deployment model. The Orchestrator daemon and the Compiler Containers it spawns are **co-deployed** directly from the same repository via `docker-compose`. 

Because they are built and started together, there is **no Version Skew possible**. (e.g., You will never have a v1 Orchestrator accidentally talking to a v2 Compiler Container).

### Triggers & CI Integration
- **When:** There is **no CI-driven SemVer Oracle pipeline** for the Orchestrator. 
- **Why:** Since there is no version skew and no external distribution, bumping a `ProtocolVersion` is meaningless dead code here.

### Local Guards (`assertions_test.go`)
Instead of a CI pipeline, the Orchestrator relies entirely on local developer guards run via `go test ./...`:

1. **`TestPortFieldParity`**: 
   Port structs (e.g., `WebhookReleasePayload`) and implementation structs (e.g., `ReleasePayload`) often represent different abstraction layers and thus have different field counts. This test ensures that any fields they **share** in common maintain the exact same Go data types.
2. **`TestSelfContainedPortsHaveTags`**: 
   A strict linter that iterates over all Orchestrator port structs (all 28 of them, covering GitHub APIs, Docker configs, and Daemon environment variables) and enforces that every single exported field has a valid `port:"required"` or `port:"optional"` tag.

### Summary of Orchestrator Boundaries
The `ports.go` in the pipeline repository explicitly documents the boundaries for:
- Orchestrator ↔ Compiler Container (via Docker Sockets/Volumes)
- Orchestrator ↔ GitHub API (Status Updates)
- GitHub ↔ Orchestrator (Incoming Webhooks)
- Orchestrator ↔ Registry (Git/File I/O)
- Hub API ↔ Clients (HTTP JSON endpoints)
- Daemon Environment Configuration
