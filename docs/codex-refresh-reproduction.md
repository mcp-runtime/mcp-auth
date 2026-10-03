# Two-process refresh and cancellation reproduction

Runtime issue [#501](https://github.com/mcp-runtime/mcp-runtime/issues/501)
requires client validation as well as server audit coverage. The fixture in
`tests/e2e/codex_refresh_cancellation.py` launches two Codex app-server processes
against a loopback OAuth issuer and MCP endpoint, using a shared temporary
credential store. It makes direct MCP reads, expires access tokens, rotates a
refresh token, unsubscribes and closes the peer, then reads again. No model
turns, existing Codex configuration, real MCP services, or user credentials are
used. The issuer rejects replay and revokes the refresh family.

Run against an explicit client binary:

```sh
python3 tests/e2e/codex_refresh_cancellation.py --codex /path/to/codex --cycles 3 --access-ttl 70
python3 tests/e2e/codex_refresh_cancellation.py --codex /path/to/codex --cycles 3 --access-ttl 5
```

Use `--legacy` for the control with refresh coordination disabled. The fixture
writes the feature selection to its temporary configuration and verifies the
effective setting through `experimentalFeature/list`. Its JSON report contains
only version, counters, selected mode, and bounded failure stages. Failure exits
nonzero; teardown is included in the success verdict. The manually dispatched
`Codex OAuth refresh reproduction` workflow pins Codex 0.159.2 and preserves
reports for both modes and lifetimes. It is diagnostic rather than a passing
gate for the auth server.

## Observed result and remaining client dependency

On Codex 0.159.2, a single coordinated five-second cycle succeeded, but repeated
cycles replayed a refresh token and revoked the family. A repeated 70-second
run completed one cycle before replay during the next rotation. The five-second
failure also reproduced after persisting and verifying the coordination feature.
Timing affects reproduction; a single legacy 70-second cycle did not replay.
Enabling the experimental feature is therefore not sufficient evidence that
the issue is fixed. These are local fixture observations, not production tests.

Source inspection at Codex `rust-v0.159.2` identified a cancellation-sensitive
path requiring a targeted upstream regression test. Coordinated proactive
refresh runs in an owned task. In its RMCP 3.2.0 dependency,
`AuthClient::get_access_token` and the reactive 401 recovery path instead await
the authorization manager inside the transport caller's future. Cancellation
can interrupt that future between the issuer consuming a refresh token and
the credential store saving its replacement. Cross-process locks alone cannot
persist a response from a cancelled request. This is a source-based hypothesis;
the fixture does not establish that every observed replay follows this path.

The client fix must preserve the refresh transaction through credential
persistence when transport work is cancelled, then pass repeated two-process
cycles. The server must retain strict replay revocation; adding a replay grace
window would conceal the client defect. The auth PR improves client binding,
atomic family revocation and safe audit evidence but does not close this client
dependency. See the [Codex app-server documentation](https://developers.openai.com/codex/app-server)
for the protocol used by the reproduction.
