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
- Install flow: `/setup` wizard → `/setup/run` (pkexec) → writes service, then the
  process SIGINTs itself so systemd claims the port. `/setup/uninstall` reverses it
  and deletes `setup.json`. `/setup/skip` records the choice.

## Session 2026-06-30 — changes made (source only; AppImage NOT rebuilt)
1. **HTTP→HTTPS fix.** Root cause was IPv6: installer writes both `127.0.0.1` AND
   `::1 thismachine.chat` to `/etc/hosts`, but server bound IPv4 only, so browsers
   resolving to `::1` got connection-refused. Made `_start_dual_mode()` and
   `_start_http_redirect()` bind **both IPv4 and IPv6 loopback** (`::1`, V6ONLY).
   `_start_http_redirect()` rewritten from `HTTPServer` to raw sockets + now logs
   whether port 80 bound. Verified: all of {v4,v6}×{http-redirect,https} work.
2. **Install prompt on every start.** Added `_should_show_setup()` — wizard
   auto-opens every launch UNLESS `never` is set or already installed (`method==admin`).
   Was previously gated on `_is_first_run()` (only first launch). Removed now-unused
   `_is_first_run()`. `/setup` route now only redirects away when `method==admin`
   (so a prior "skip" still re-shows the wizard, and Settings→Install can reach it).
3. **Install/uninstall always in Settings.** `openSettings()` JS always shows the
   System Setup section: "Set Up System Service…" (`goInstall()` → `/setup`) when not
   installed, "Uninstall System Setup" when installed. Added `#install-btn`.
4. **Post-install handoff hang fixed.** Wizard used to poll
   `fetch('https://thismachine.chat', {mode:'no-cors'})` to detect the new
   service — impossible: a background fetch rejects on the freshly-regenerated
   **self-signed cert** (no-cors ≠ skip cert check), and probing over HTTP is
   mixed-content-blocked from the https:5000 page. So "Handing off…" spun forever.
   New flow: in user mode (port≠443) `setup_run` **keeps the old process alive**
   instead of self-SIGINTing, returns `{ok, keepalive, target}`. Added
   `/setup/probe` (same-origin; raw TCP connect to 127.0.0.1:443 — cert-agnostic)
   and `/setup/done` (client tells leftover process to exit). JS polls
   `/setup/probe`, then does a **top-level navigation** to thismachine.chat (the
   only thing that lets the user click through the cert warning), with a 60 s
   safety valve + manual "Open" button. Edge case port==443: still self-SIGINTs,
   falls back to a timed navigation. Verified on 5000: probe returns up:false, all
   routes respond.

### TODO / follow-ups
- **Rebuild the AppImage** (`./build-appimage.sh`) — `build/ThisMachine-x86_64.AppImage`
  is stale and won't have these changes.
- Couldn't fully reproduce installed mode (port 443/80 needs systemd/root; the
  service was installed but inactive). Fixes were validated on port 5000. Worth a
  real installed-mode smoke test of `http://thismachine.chat` → HTTPS.
- IPv6 fix only helps loopback (`HOST` defaults to `127.0.0.1`). If `TERMSITE_HOST`
  is a non-loopback address, the `::1` listener is skipped by design.
