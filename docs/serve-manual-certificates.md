# Using manual TLS certificates with Tailscale Serve

Tailscale Serve normally provisions TLS certificates automatically for a
node's MagicDNS name. To use a certificate managed outside Tailscale, pass its
certificate and private key files to `tailscale serve`:

```sh
tailscale serve --bg \
  --cert-file=/etc/tailscale/serve/fullchain.pem \
  --key-file=/etc/tailscale/serve/private-key.pem \
  localhost:3000
```

This starts the default HTTPS listener on port 443. Use `--https` to select a
different port:

```sh
tailscale serve --bg --https=8443 \
  --cert-file=/etc/tailscale/serve/fullchain.pem \
  --key-file=/etc/tailscale/serve/private-key.pem \
  localhost:3000
```

The two flags must be used together. They are supported for HTTPS and
TLS-terminated TCP listeners, but not for plain HTTP, unterminated TCP, or
Tailscale Funnel.

## Custom domain names

A manual certificate can contain any domain name. Serve does not create or
modify DNS records for that domain. Configure the domain to resolve to the
Tailscale IP address of the node, and ensure the certificate's subject
alternative names include the domain used by clients.

For example, after configuring `app.example.com` in DNS, the command above can
serve requests for `https://app.example.com` to tailnet clients. In manual
certificate mode, Serve selects the HTTPS handler by listener port rather than
requiring the TLS SNI name to match the node's MagicDNS name.

Serve can fall back to port-based routing only when it finds one web server
configuration for that port. Multiple host configurations at the same routing
precedence are ambiguous, so no handler is selected.

## Certificate files

The certificate file must contain a PEM-encoded leaf certificate followed by
any intermediate certificates. The key file must contain the corresponding
PEM-encoded private key and must not require an interactive passphrase.

The CLI converts relative file names to absolute paths before saving the Serve
configuration. The files are read by `tailscaled`, not by the CLI process, so
they must remain at those paths and be readable by the account running
`tailscaled`.

Setting a Serve configuration that references a private key requires local
administrator authorization. Keep the private key readable only by the daemon
account where possible.

## Automatic reload

`tailscaled` reads and validates both files for every new TLS handshake. A
valid replacement is therefore used by the next connection without changing
the Serve configuration or restarting the daemon. Existing TLS connections
continue using the certificate with which they were established.

Certificate renewal tools commonly replace the certificate and key in separate
file operations. During that interval, the two files may not match. After at
least one valid certificate has been loaded from the configured paths,
`tailscaled` keeps serving that certificate while an update is:

- temporarily mismatched;
- malformed; or
- temporarily missing one of the files.

The first distinct reload failure is written to the `tailscaled` log. Repeated
handshakes with the same failure do not repeat the message. A successful
recovery is also logged.

Replace files atomically where practical by writing a temporary file in the
same directory and renaming it over the old file. The certificate and key may
be renamed in either order; the last valid pair remains available between the
two operations.

The fallback certificate is held only in memory and applies only to the same
configured paths. It is not used after changing `--cert-file` or `--key-file`
to another path, and it is lost when `tailscaled` restarts. Consequently, both
files must contain a valid matching pair before changing paths or restarting
the daemon.

## TLS-terminated TCP

The same certificate can terminate TLS before forwarding a raw TCP stream:

```sh
tailscale serve --bg --tls-terminated-tcp=8443 \
  --cert-file=/etc/tailscale/serve/fullchain.pem \
  --key-file=/etc/tailscale/serve/private-key.pem \
  tcp://127.0.0.1:5432
```

The reload behavior is identical to HTTPS Serve.

## Interaction with automatic certificates

When a listener has manual certificate files, Serve does not request an
automatically provisioned certificate and does not enable ACME TLS-ALPN
challenges on that listener. Other listeners without manual certificate files
may continue using automatic certificates.

All manual TLS listeners in one Serve configuration must use the same
certificate and key paths. This includes node listeners, service listeners,
and foreground Serve sessions.

## Stopping the listener

Do not repeat the certificate flags when turning a listener off:

```sh
tailscale serve --https=443 off
```

For TLS-terminated TCP, use its listening port:

```sh
tailscale serve --tls-terminated-tcp=8443 off
```

## Troubleshooting

- **The configuration is rejected:** Confirm that both flags are present, the
  paths identify a valid matching pair, and the command has local administrator
  authorization.
- **The handshake fails after a daemon restart:** The on-disk files are invalid,
  mismatched, missing, or unreadable. The in-memory fallback does not survive a
  restart.
- **Clients report a hostname mismatch:** Add the custom domain to the
  certificate's subject alternative names and verify that clients use that
  name.
- **A renewed certificate is not visible:** Start a new TLS connection and
  inspect the `tailscaled` log for a manual certificate reload failure.
