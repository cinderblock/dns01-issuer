# dns01-issuer

**CSR in, certificate out, by ACME DNS-01, for names bound to key fingerprints in its config.**

Give a fleet of devices publicly trusted certificates without giving any of them a DNS credential. Each device makes its own key, which never leaves it, and sends a certificate signing request. The issuer holds the DNS token, runs the DNS-01 challenges against your CA (Let's Encrypt, or any RFC 8555 CA), renews on its own schedule, and hands the latest certificate to whichever device holds the bound key.

What may be issued is decided by **one config file**: each entry binds an exact set of DNS names to the SHA-256 fingerprint of one public key. There is no admin login and no approve button. Approving a device means adding its entry, so the review that config already gets (a commit, a pull request) is the approval.

## How it decides

- A CSR is accepted only if its names are **exactly** an entry's name set (no more, no less) and its public key's fingerprint is that entry's `key`.
- Anything else is refused (`403`) and listed on the status page with its fingerprint and a ready-to-paste config entry. Nothing is issued for it.
- A CSR proves possession of its key: its signature is verified before anything else.
- Certificates are public (they're in the Certificate Transparency logs), so fetching one needs no authentication.
- Check-ins are signed with the device's bound key and timestamped. A replay, or a clock more than 5 minutes off, is refused.

## Issuance and renewal

- One order at a time. Challenge records are always removed afterwards, success or failure.
- Before asking the CA to validate, it waits until the challenge TXT is visible on **every authoritative server** of the zone. A recursive resolver could have cached the name's absence for the zone's negative TTL.
- Renewal happens at a random point inside the CA's [ARI](https://www.rfc-editor.org/rfc/rfc9773) window when the CA offers one, otherwise at two thirds of the certificate's lifetime. The new order names the certificate it `replaces`.
- Failures are retried with backoff (5 minutes, doubling, capped at 24 hours) and shown on the status page with the CA's or DNS provider's error.
- **Preconditions,** per entry:
  - `require_public_dns: true`: don't issue until the name resolves in public DNS. This is useful when the name and the "leave this challenge record alone" rule for whatever else manages your zone are created together; seeing the name proves the rule is in place.
  - `inside_resolver: <ip>`: for status only. Shows what a private resolver (split-horizon DNS) answers for the name, beside the address the device last checked in from.

## Config

The path is in `DNS01_ISSUER_CONFIG`. Every key is checked at startup, and unknown keys are errors.

```yaml
acme:
  directory: https://acme-v02.api.letsencrypt.org/directory
  contact: [mailto:you@example.com] # optional
  terms_of_service_agreed: true # required, and must be true
data_dir: /data # SQLite state and the ACME account key
listen: { hostname: 0.0.0.0, port: 8080 }
trusted_proxies: [172.16.0.0/12] # peers whose X-Forwarded-For (rightmost entry) is believed
display_timezone: America/Los_Angeles # status page; default UTC
public_dns: { doh: https://cloudflare-dns.com/dns-query } # default; or { nameservers: [ip, ...] }
zones:
  - zone: example.com
    provider: cloudflare
    token_env: CF_DNS_TOKEN # the env var holding the API token
    zone_id: 0123abcd # optional; without it the token also needs Zone:Read
certificates:
  - name: device-1.fleet.example.com
    alt_names: [] # optional
    key: sha256/K3X0...= # see "Fingerprints"
    require_public_dns: true # optional
    inside_resolver: 10.0.0.1 # optional
```

**Cloudflare token:** `Zone:DNS:Edit` on the zone (plus `Zone:Read` without `zone_id`). Challenge records get a comment saying what made them.

## Fingerprints

`sha256/` followed by the base64 of SHA-256 over the DER SubjectPublicKeyInfo (the HPKP pin format):

```sh
openssl pkey -in key.pem -pubout -outform DER | openssl dgst -sha256 -binary | openssl base64 -A
```

`dns01-issuer-client fingerprint` prints it, together with the config entry to add.

## API

| Method and path                                           | Auth                                                             | Result                                                                               |
| --------------------------------------------------------- | ---------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| `POST /api/v1/csr` (PEM body)                             | the CSR's own signature                                          | `202` queued, `200` already current, `403` unbound (with fingerprint), `400` bad CSR |
| `GET /api/v1/certificates/<name>`                         | none                                                             | full-chain PEM, or `404`                                                             |
| `POST /api/v1/checkin` (JSON body, `X-Signature: base64`) | ECDSA/RSA SHA-256 signature by the bound key over the exact body | `200` with the current serial and expiry                                             |
| `GET /`                                                   | none                                                             | read-only status page                                                                |
| `GET /healthz`                                            | none                                                             | `ok <build>`                                                                         |

A check-in body needs `"name"` (the entry's primary name) and `"time"` (Unix seconds). Anything else in it is shown on the status page; the client sends its addresses, its own lookup of its name, and its installed serial.

## The device client

`client/dns01-issuer-client` is a bash script that needs only `openssl` (1.1.1+) and `curl`. Install it with its systemd units:

```sh
install -m 755 client/dns01-issuer-client /usr/local/bin/
install -m 644 client/dns01-issuer-client.service client/dns01-issuer-client.timer /etc/systemd/system/
install -m 600 client/dns01-issuer-client.conf.example /etc/dns01-issuer-client.conf   # then edit it
dns01-issuer-client fingerprint      # makes the key; add the printed entry to the issuer's config
systemctl enable --now dns01-issuer-client.timer
```

Each run:

- sends the (stable) CSR;
- fetches the current chain, waiting up to `WAIT_SECONDS` if it was only just queued;
- installs the chain only if it is unexpired, for this key and for these names, then runs `RELOAD`;
- checks in.

It exits `3` while the key isn't bound yet.

## Running it

```sh
docker run -v ./issuer.yaml:/config/issuer.yaml:ro -v issuer-data:/data -e CF_DNS_TOKEN=... -p 127.0.0.1:8080:8080 ghcr.io/cinderblock/dns01-issuer:<sha>
```

The image runs as the unprivileged `bun` user and keeps its state in `/data`. Put it behind a TLS-terminating reverse proxy and list that proxy in `trusted_proxies`.

## Development

```sh
bun install
bun run typecheck && bun run format:check
bun run test        # unit tests
bun run test:e2e    # against Pebble; needs pebble and pebble-challtestsrv on PATH
```

Install Pebble with `go install github.com/letsencrypt/pebble/v2/cmd/{pebble,pebble-challtestsrv}@v2.10.1`. The end-to-end suite runs a real ACME flow: refusals, the public-DNS wait, issuance, challenge cleanup, ARI, renewal with `replaces`, signed check-ins, and the shell client itself.

## License

MIT. `test/pebble/` holds Pebble's public test certificates (MPL-2.0); see its README.
