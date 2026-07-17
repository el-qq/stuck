# NGFW lab-data utility

`backend/tools/ngfw_testdata` is a separate administration command that creates
prefixed users, objects and rules for manual STUCK verification.

> Warning: this command changes NGFW configuration. Use it only on an authorized
> lab system. The STUCK application itself remains read-only. The utility and
> its rollback are provided AS IS; inspect `--dry-run` before applying changes.

## Run

Create the backend environment first with `npm run setup`. Then run from
`backend/`:

```bash
# Read-only plan; login and password are prompted.
.venv/bin/python -m tools.ngfw_testdata \
  --target ngfw.example.test:8443 \
  --dry-run

# Apply the plan.
.venv/bin/python -m tools.ngfw_testdata \
  --target ngfw.example.test:8443
```

`--target` is required and uses `host:port` without scheme or path. Login is
prompted unless `--login` is supplied; the administrator password is always
read without echo. For automation, use `NGFW_ADMIN_PASSWORD` and
`NGFW_TEST_USER_PASSWORD` environment variables instead of command arguments.

TLS is encrypted but certificate verification is disabled by default for lab
appliances with self-signed certificates. Use `--verify-tls` for the system CA
store or `--ca-bundle <path>` for a private CA.

Useful options:

- `--prefix "STUCK TEST"` — resource prefix and ownership marker;
- `--parent-group-id group.id.1` — existing parent for the test group;
- `--test-user-login <login>` and `--test-user-password <password>`;
- `--include-dns` — create the optional test forward zone;
- `--enable-modules` — enable content filter and IPS globally;
- `--dry-run` — GET-only plan with no writes.

## Managed resources

The default prefix is `STUCK TEST`; comments use `[STUCK TEST]`. A different
prefix isolates another dataset.

| Resource                               | Test purpose                               |
| -------------------------------------- | ------------------------------------------ |
| Local group and user                   | User/group-scoped rules                    |
| `203.0.113.10` IP object               | Firewall reject                            |
| `example.org` domain object            | Firewall drop                              |
| `198.51.100.25` and port `9443`        | Ordered IP:port drop before general accept |
| `192.0.2.30` IP object                 | IPS bypass                                 |
| `cf-block.example` category/rule       | Content-filter deny                        |
| `cf-redirect.example` category/rule    | Content-filter redirect                    |
| optional `stuck-dns.test` forward zone | NGFW DNS forwarding                        |

All addresses and domains are documentation ranges. After applying, refresh
rules in STUCK because the application snapshot is intentionally not
invalidated by an external configuration change.

## UI verification matrix

Select the generated test user for scoped cases.

| Target                | Expected result                                 |
| --------------------- | ----------------------------------------------- |
| `example.com`         | no test rule blocks                             |
| `cf-block.example`    | blocked at content filter by deny               |
| `cf-redirect.example` | blocked at content filter by redirect           |
| `example.org`         | blocked at firewall by drop                     |
| `203.0.113.10`        | blocked at firewall by reject                   |
| `198.51.100.25:9443`  | blocked by the earlier exact port rule          |
| `198.51.100.25:443`   | exact rule misses; later general accept matches |
| `192.0.2.30`          | IPS bypass when IPS is enabled                  |

Managed firewall/content rules are placed before existing rules and verified
after creation. This preserves first-match semantics even on appliances with
large rule tables.

## Safety and failure behavior

- Existing matching resources are reused and reported as `[EXISTS]`.
- A matching name with different content is a conflict; nothing is overwritten.
- Created address/domain/port objects are read back and validated.
- On failure, best-effort rollback removes only resources created by that run.
- A read-only administrator receives a clear permission error.
- Authentication, permission, TLS/network, API-shape and resource-conflict
  failures use distinct exit codes.
- Passwords and cookies are never printed.

The default local-user root is `group.id.1`. Some NGFW releases accept or
return its raw numeric form; the utility resolves both forms before creation.

## Relevant vendor sources

Use `docs/source/toc.yaml` to route to administrator login, users, objects,
firewall, content filter, IPS exceptions and DNS documentation. Shaper endpoints
are read-only UI-observed APIs and are not used to seed rate-limit rules.
