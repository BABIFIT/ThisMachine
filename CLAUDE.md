# ThisMachine — agent notes

Terminal-in-a-browser (iMessage-style shell). Single-file app: `thismachine.py`
(Flask + embedded HTML/JS, ~2600 lines). Packaged as an AppImage via
`build-appimage.sh`. Run from source with `./start.sh` (creates `.venv`).

## Architecture quick map (`thismachine.py`)
- `_ensure_tls()` — auto-generates self-signed cert in `~/.termsite_cert/` (or
  uses mkcert certs). SAN covers `thismachine.localhost`, `thismachine.chat`, `localhost`.
- `BROWSER_HOST` — `thismachine.chat` if it's in `/etc/hosts` (installed), else
  `thismachine.localhost`. Default port 443, falls back to 5000 without privilege.
- Setup/install state: `~/.config/thismachine/setup.json`
  (`{done, method: "admin"|"skip", never}`). `method=="admin"` = systemd service
  installed (`/etc/systemd/system/thismachine.service`, port 443, runs the AppImage).
- `_run_server()` → `_start_dual_mode()`: one socket per port that peeks the first
  byte — `0x16` (TLS) tunnels to inner Flask on `PORT+10000`; anything else gets a
  301 to HTTPS. `_start_http_redirect()` does the same for port 80.
- Both listeners bind **IPv4 and IPv6 loopback** (`::1`, V6ONLY). This matters:
  the installer writes both `127.0.0.1` and `::1 thismachine.chat` to `/etc/hosts`,
  so a browser resolving to `::1` gets connection-refused if only IPv4 is bound.
  Only applies to loopback — a non-loopback `TERMSITE_HOST` skips the `::1`
  listener by design.
- Install flow: `/setup` wizard → `/setup/run` (pkexec) → writes the service unit.
  In user mode (port≠443) the old process **stays alive** rather than self-SIGINTing;
  `/setup/run` returns `{ok, keepalive, target}`, the client polls `/setup/probe`
  (same-origin raw TCP connect to 127.0.0.1:443, so it's cert-agnostic), then does a
  **top-level navigation** to `thismachine.chat` — the only thing that lets the user
  click through the self-signed cert warning — and calls `/setup/done` to retire the
  leftover process. A background `fetch()` cannot work here: no-cors does not skip
  the cert check, and probing over HTTP is mixed-content-blocked. When port==443 the
  process self-SIGINTs so systemd can claim the port.
- `/setup/uninstall` reverses the install and deletes `setup.json`; `/setup/skip`
  records the choice. `_should_show_setup()` re-opens the wizard on every launch
  unless `never` is set or `method=="admin"`.
