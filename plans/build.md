# dns01-issuer: build plan

`plans/build.md`

## Goal

A small, generic certificate issuer: **CSR in, certificate out, by ACME DNS-01**, for names bound to public-key fingerprints in its config. Devices keep their private keys and never hold a DNS credential. The issuer holds the DNS token, runs the challenges, renews on its own schedule, and hands the latest certificate to whichever device holds the bound key.

First user: a fleet of robots, deployed from a separate infrastructure repo that holds the config file, the DNS token and the image pin. Nothing specific to one deployment belongs in this repo.

## Environment / context

- Published as `cinderblock/dns01-issuer` (the working name became the final one).
- Runtime: Bun 1.4.2 (Bun's built-in YAML parser, `bun:sqlite`, `node:dns/promises` `Resolver` with explicit servers, WebCrypto).
- Dependencies: `@peculiar/x509` (CSR and certificate parsing and verification). Nothing else at runtime.
- Test CA: Pebble + `pebble-challtestsrv` (Let's Encrypt's test ACME server and its mock DNS), from `go install github.com/letsencrypt/pebble/v2/cmd/...@latest` (into `$(go env GOPATH)/bin`).
- Deployment: this repo's CI builds `ghcr.io/cinderblock/dns01-issuer:<sha>` with an `org.opencontainers.image.revision` label, and stops there. The deployer pins the digest and supplies the config file and token.

## Decisions already made (don't re-ask)

- **Own RFC 8555 client on WebCrypto**, not `acme-client` (last published 2024-07; pulls in axios and node-forge) and not lego (shelling out, parsing output). It is small, follows the current RFCs (including ARI, RFC 9773) and is tested end to end against Pebble.
- **Approval is configuration.** A certificate is issued only for a CSR whose public key's SHA-256 SPKI fingerprint equals the `key:` bound to exactly that name set in the config. There is no admin login and no approve button; the status page is read-only. Unbound requests are listed with their fingerprint so it can be copied into the config.
- **No authentication to fetch a certificate:** certificates are public (CT logs).
- **Check-ins are signed with the device's key** (the key bound in config); a timestamp window and a strictly increasing timestamp stop replays.
- **Exact name sets.** A config entry is a certificate: `name` plus optional `alt_names`. A CSR must ask for exactly that set, no more and no less.
- **Preconditions before issuing**, per entry: `require_public_dns` (the name resolves publicly; useful when whatever manages the zone creates the name together with its rule protecting the challenge records) and an optional `inside_resolver` check (status only).
- **One issuance at a time**, serialized, with exponential backoff on failure (5 min doubling, 24 h cap).
- **Renewal:** at a random point in the ARI suggested window when the CA offers ARI; otherwise at two thirds of the lifetime. A new order names the certificate it replaces.
- **Errors propagate.** Bad config fails startup with the file and the key named; no silent defaults for anything deployment-specific.

## Design

### Config (YAML; the path is in `DNS01_ISSUER_CONFIG`)

```yaml
acme:
  directory: https://acme-v02.api.letsencrypt.org/directory
  contact: [mailto:someone@example.com] # optional
  terms_of_service_agreed: true # required, must be true
data_dir: /data
listen: { hostname: 0.0.0.0, port: 8080 }
trusted_proxies: [172.16.0.0/12] # peers whose X-Forwarded-For is believed; optional
display_timezone: America/Los_Angeles # optional, default UTC
public_dns: { doh: https://cloudflare-dns.com/dns-query } # or { nameservers: [...] }
zones:
  - zone: example.com
    provider: cloudflare
    token_env: CF_DNS_TOKEN
    zone_id: 0123abcd # optional; lets the token drop Zone:Read
certificates:
  - name: device-1.fleet.example.com
    alt_names: [] # optional
    key: sha256/<base64 of SHA-256 over the SubjectPublicKeyInfo DER>
    require_public_dns: true # optional
    inside_resolver: 10.0.0.1 # optional, status only
```

### API

| Method and path                                   | Auth                            | What it does                                                                                                                                                                                             |
| ------------------------------------------------- | ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `POST /api/v1/csr` (PEM body)                     | none; the CSR proves possession | Verifies the CSR. If its names and key match an entry, stores it and queues issuance (`202`), or reports the current certificate (`200`). Otherwise records it as unbound (`403`, with the fingerprint). |
| `GET /api/v1/certificates/<name>`                 | none                            | The current full-chain PEM, `404` if none.                                                                                                                                                               |
| `POST /api/v1/checkin` (JSON body, `X-Signature`) | signature by the bound key      | Records the time, the device's addresses and its own lookup of its name.                                                                                                                                 |
| `GET /`                                           | none                            | Read-only status page.                                                                                                                                                                                   |

### Modules

- `src/config.ts`: load and validate.
- `src/keys.ts`: SPKI fingerprints, signature verification.
- `src/csr.ts`: parse and verify CSRs.
- `src/acme/`: JWS, the RFC 8555 client, ARI.
- `src/dns/`: provider interface, Cloudflare, challtestsrv (tests), propagation and public/inside checks.
- `src/store.ts`: SQLite.
- `src/issuer.ts`: intake, scheduling, issuance and renewal.
- `src/server.ts`: HTTP and source-IP handling.
- `src/status-page.ts`: HTML.
- `client/`: the device script and its systemd units.

## Plan / steps

1. [x] Scaffold: package.json, tsconfig, prettier, plan.
2. [x] Config, keys, CSR, with unit tests.
3. [x] ACME client and ARI, with unit tests where they don't need a CA.
4. [x] DNS providers and checks.
5. [x] Store, issuer, server, status page.
6. [ ] Client script and systemd units. **(current)**
7. [x] End-to-end test against Pebble: unbound refused, bound issued, fetched, checked in, renewed with `replaces`. 9 tests, ~7 s.
8. [ ] Dockerfile (base image pinned by digest), CI workflow (test, e2e, build, push), README.
9. [ ] Cameron: final name, then create the GitHub repo and push.

## Findings / gotchas

- **`@peculiar/x509` 2.x needs `reflect-metadata` loaded first** (its tsyringe container). Without it the import throws `tsyringe requires a reflect polyfill`. `src/x509.ts` is the single import site that guarantees the order.
- **Look extensions up by OID, not class.** With @peculiar/x509 2.2.0 under Bun 1.4, `getExtension(SubjectAlternativeNameExtension)` returned null for a CSR that has a SAN; `getExtension('2.5.29.17')` returns it. Cause not investigated.
- **`lib` has no DOM,** so `BufferSource` and `JsonWebKey` aren't global types; each file that needs one defines it locally.
- **Pebble's test localhost certificate expires 2027-10-03** (`test/pebble/README.md`). The e2e test fails after that until the files are refreshed from a newer Pebble.
- **challtestsrv answers every A/AAAA query with 127.0.0.1/::1 by default.** The e2e test passes `-defaultIPv4 '' -defaultIPv6 ''` so that "not in public DNS" can be tested; names get addresses only through `/add-a`.
- **An unverified test vector was caught.** The first JWK thumbprint test asserted a value that had never been computed independently, and it failed. It now checks the canonical form; the Pebble run is the independent check, since a wrong thumbprint fails DNS-01.

## Progress log

- [x] 2026-10-26 ~2:05 AM PDT (09:05Z): core issuer written; 25 unit tests and 9 Pebble e2e tests pass; typecheck clean.
- [ ] Client script, Dockerfile, CI, README

## Things not to do

- Don't generate or store any device's private key.
- Don't issue for a CSR whose name set or key doesn't match an entry exactly.
- Don't add behaviour specific to one deployment; put it in config.
- Don't swallow errors: surface them on the status page and in logs.
