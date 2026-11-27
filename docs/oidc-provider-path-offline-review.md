# Storage checker URL compatibility and failure stages — offline delta

Base protected sandbox main: `a05dc9b04fe5bfedb99e8fc8d0f093e5e8efa60c`.
Fresh read-only branch response matched and reported `protected: true`. Its embedded protection summary also said `enabled: false`; effective protection rules were not independently audited or changed. Local callee blob is `4f731befafbee6633b319083678186a82f16c274`, identical to commit `5c91fb3bc1f5ffc04af51eebeae9f055063e918e`. Caller blob remains `3a8ddaa802d35783754aea631ba753649106f389`.

Parent reports run 46050546598 attempt 1 had intended owner approval but capture exited 78 without receipt or root-stage detail. No token/run logs were collected here. The demonstrated parser incompatibility is a likely hypothesis, **not confirmed cause** of that run failure. Approval evidence is supplied context, not a newly verified live result.

## Narrow URL grammar

The prior guard accepted only paths starting with `/_apis/`. The firsthand diagnostic report in [google-github-actions/auth issue 455](https://github.com/google-github-actions/auth/issues/455) shows a regional GitHub pipeline origin with an opaque scope segment and GUID before that API route. The [runner connection documentation](https://github.com/actions/runner/blob/main/docs/checks/actions.md) describes root `/_apis/` service paths. These are compatibility evidence, not a universal stable OIDC endpoint specification or proof about this run. No published live-looking endpoint values were copied into fixtures.

Accept a complete exact route ending in `/distributedtask/hubs/Actions/plans/<guid>/jobs/<guid>/idtoken` below `/_apis`, either at root or preceded by exactly two scoped segments. Scoped form additionally requires a single `pipelinesghub<lowercase-alphanumeric-suffix>` hostname under `actions.githubusercontent.com`; opaque scope is 1–128 ASCII alphanumeric/underscore/hyphen, followed by a lowercase GUID. GUID grammar is lowercase 8-4-4-4-12 hex. Root form retains the existing strict GitHub hostname allowance. No trust origin is broadened. Unknown future variants fail closed for review.

Retain HTTPS only, canonical authority without port/userinfo, existing total URL length/ASCII checks, no backslash/fragment. Full path match rejects percent encodings, traversal, repeated separators, added segments and substring tricks. Query accepts only absent query or literal `api-version=2.0`, then appends the unchanged fixed audience once; encoded/duplicate/unknown/credential/audience query fields are rejected. This intentionally narrows old permissive query/path acceptance. Other API versions remain unsupported without evidence/review. Tests use all-zero synthetic GUIDs and a synthetic scope/region name; they do not access those hosts.

## Fixed failure stages

Failure output is now exactly `STOP: claim proof refused stage=<code>` on stderr, exit 78, with no stdout receipt. Codes are GATE, CONTEXT, PROVIDER_URL, REQUEST_CREDENTIAL, TRANSPORT, ASSERTION, CLAIMS, INTERNAL. They locate the last attempted boundary, not a root-cause diagnosis. Exceptions are converted to an allowlisted code; arbitrary exception messages, raw URLs/headers/tokens/claim values and tracebacks are never printed at the failure boundary. Success receipt schema remains byte-for-byte implemented as before.

Only provider_url, collect boundary diagnostics and main failure formatting change, plus the stage exception/constant. All existing runner/actor/repo/ref/audience/claim checks, no-proxy/no-redirect single bounded GET, RELEASED setting, workflow gate, trigger, environment, permissions, timeout and runner remain unchanged. No Azure code. The embedded claim observer still does not validate JWT signatures; exact reviewed callee SHA and same-run owner approval require external verification as before. Self-consistent workflow SHA claims alone do not establish exact reviewed identity.

## Offline checks and future gates

`python -I tests/test_oidc_path_offline.py -v` and `python -I -O tests/test_oidc_path_offline.py -v` use existing PyYAML. Tests extract the actual YAML Python heredoc, execute it with credential-free synthetic environment, deny socket/DNS/urlopen, and replace only provider transport with in-memory fixtures. They exercise the complete `__main__` entrypoint with mocked transport, plus failure boundaries and preserved control assertions. No runner workflow body is executed; no real credential, token request or service call occurs. Synthetic JWT-shaped fixture strings are fabricated data, not acquired credentials or valid signed assertions.

Local candidate only; caller and dispatcher unmodified. This candidate's new callee bytes require a separately reviewed exact future commit pin, caller plan and dispatcher/run-inventory plan before any publication or another run. Do not reuse the earlier one-attempt dispatch authorization. Fresh App/environment/owner approval and cleanup requirements remain; this offline result authorizes none of them. No push, PR, merge, CI, access change or spend.
