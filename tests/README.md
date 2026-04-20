# Tests

Cross-platform Rust test suite for the interceptor and the end-to-end pipeline. The same `make` targets work on Linux, macOS, and Windows.

## Layout

```
tests/
├── src/
│   ├── interceptor.rs      # Helpers to spawn the interceptor binary
│   ├── mock_broker.rs      # In-process mock broker over AF_UNIX (uds_windows on Windows)
│   ├── e2e.rs              # Harness that boots a real Falco + plugin + rules
│   └── lib.rs              # Re-exports
├── tests/
│   ├── interceptor.rs      # Unit tests against the mock broker
│   ├── e2e.rs              # End-to-end enforcement-mode tests
│   └── e2e_monitor.rs      # End-to-end monitor-mode tests
└── test_installed_service_windows.ps1   # Optional post-install smoke test (Windows)
```

## Running the tests

All targets are invoked from the repository root via `make`.

```bash
make test-interceptor    # Interceptor unit tests — no Falco required
make test-e2e            # End-to-end tests — require Falco + plugin to be built
make test                # Both
```

On Windows, run the same commands from a shell where `make` is available (GnuWin32 / Chocolatey `choco install make`).

### `make test-interceptor`

Runs `cargo test --test interceptor`. Spawns the built `claude-interceptor` binary and points it at an in-process mock broker (`tests/src/mock_broker.rs`) over a temporary AF_UNIX socket. Covers: allow / deny / ask round-trips, broker-unavailable fail-closed behavior, malformed broker responses, wire-protocol ID mismatch, slow broker (timeout enforcement), oversized input.

Requires only a built interceptor. On any OS:

- Build first: `make build-interceptor`
- Run: `make test-interceptor`

### `make test-e2e`

Runs `cargo test --test e2e --test e2e_monitor`. Boots a real Falco process with the built plugin shared library, writes rule files and a Falco config to a temp dir, then drives the real interceptor → broker → Falco → HTTP alert → verdict resolution pipeline. Covers: deny rules, ask rules, allow (seen), verdict escalation, path resolution, multiple tool types, monitor-mode bypass.

Requires the whole stack built:

- Build components: `make build`
- Have Falco available:
  - Linux: `make download-falco-linux`
  - macOS: `make falco-macos`
  - Windows: `make falco-windows-x64` or `make falco-windows-arm64` (requires `VCPKG_ROOT` set and vcpkg's `curl` installed for the target triplet)
- Run: `make test-e2e`

The harness (`tests/src/e2e.rs`) auto-discovers the Falco binary under `build/falco-*/...` relative to the project root. It skips gracefully (no failure) if the binary or the plugin is missing, so the tests can run in environments where Falco is not available without red CI.

### Environment overrides

| Variable | Purpose |
|----------|---------|
| `FALCO`  | Absolute path to a `falco` / `falco.exe` to use instead of auto-discovery |
| `HOOK`   | Absolute path to a `claude-interceptor` / `.exe` to use instead of auto-discovery |

Example (Windows PowerShell):

```powershell
$env:FALCO = "C:\Users\me\repos\coding-agents-kit\build\falco-0.43.0-windows-arm64\falco.exe"
make test-e2e
```

## Windows: installed-service smoke test

`test_installed_service_windows.ps1` is a standalone smoke test for a **locally installed** build of coding-agents-kit. It exercises the full user-facing stack: launcher → Falco → plugin → rules → real interceptor — using the binaries already deployed under `%LOCALAPPDATA%\coding-agents-kit\`. It is **not** invoked by `make test` because it depends on a prior MSI install.

```powershell
# Install first via the MSI + postinstall (see installers/windows/README.md), then:
powershell -ExecutionPolicy Bypass -File tests\test_installed_service_windows.ps1
```

Use this when you want to confirm that an MSI-installed build works end-to-end in a realistic environment.

## Known caveats

- **AF_UNIX paths on Windows**: the interceptor, plugin and mock broker all bind and connect using forward slashes (`C:/Users/.../broker.sock`) because Windows `AF_UNIX` treats the path as an opaque address — the two ends must use the exact same form. The harness and `mock_broker::temp_socket_path` normalize separators accordingly.
- **Port collisions**: the e2e harness picks an HTTP port deterministically from the process PID (`19000 + pid%1000`). If you happen to run two test binaries with colliding IDs concurrently, one will fail to bind.
