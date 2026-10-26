# Pebble test certificates

Copied unchanged from [Pebble](https://github.com/letsencrypt/pebble) v2.10.1, `test/certs/`
(Mozilla Public License 2.0). They exist only so the end-to-end test can talk TLS to a
local Pebble. The keys are public test keys and protect nothing.

- `localhost-cert.pem`, `localhost-key.pem`: Pebble's own HTTPS certificate (localhost, 127.0.0.1).
  **Expires 2027-10-03.** Refresh both from a newer Pebble release before then.
- `minica.pem`: the root that signed it, passed to the issuer as `acme.ca_bundle`.
