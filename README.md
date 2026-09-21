# ThisMachine

A terminal in your browser, styled like a messaging app. Commands go out as
messages, output comes back as replies — with a real PTY underneath, so
interactive programs, colors, and `sudo` prompts all work.

It binds to loopback only and is meant for driving *your own* machine from a
browser tab on that same machine.

---

## Quick start

```bash
git clone https://github.com/BABIFIT/thismachine.git
cd thismachine
./start.sh
```

Then open **https://thismachine.localhost:5000**.

`start.sh` creates a `.venv`, installs the two dependencies, and launches the
server. The only requirements are Python 3.10+ and a Linux/macOS system with
`pty` support.

### About the certificate warning

On first run a self-signed certificate is generated in `~/.termsite_cert/`.
Your browser will warn about it once — click **Advanced → Proceed**. If you'd
rather have a green padlock, install [mkcert](https://github.com/FiloSottile/mkcert)
and generate certs into `~/.termsite_cert/`; the app picks them up
automatically. The exact instructions are printed at startup.

---

## Features

- **Real PTY sessions** — interactive TUIs, colors, and job control, streamed
  to the browser over SSE.
- **Native `sudo` handling** — password prompts are detected and surfaced as a
  proper dialog instead of a blind echo-less line. Passwords are encrypted in
  memory and cleared after five minutes or on failure.
- **Tab completion** and persistent history (`~/.termsite_history.json`).
- **Installable as a PWA** — manifest and service worker included.
- **HTTPS by default**, with plain HTTP redirected to it on both IPv4 and IPv6
  loopback.
- **Optional system install** — a setup wizard adds `thismachine.chat` to
  `/etc/hosts` and installs a systemd unit on port 443, so the URL is just
  `https://thismachine.chat` with no port suffix. Fully reversible from
  Settings → Uninstall.

---

## Configuration

All settings are environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `TERMSITE_PORT` | `443` | Listen port. Falls back to `5000` without the bind capability. |
| `PORT` | — | Shorthand alias for `TERMSITE_PORT`, honored by `start.sh`. |
| `TERMSITE_HOST` | `127.0.0.1` | Bind address. **Changing this exposes your shell to the network.** |
| `TERMSITE_BROWSER_HOST` | auto | Hostname used in printed/opened URLs. |
| `TERMSITE_HISTORY_FILE` | `~/.termsite_history.json` | Where history is stored. |
| `TERMSITE_OPEN_BROWSER` | `0` (`1` in the AppImage) | Open a browser tab on start. |

To bind port 443 without the systemd install:

```bash
sudo setcap cap_net_bind_service=+ep "$(readlink -f "$(which python3)")"
```

Note this applies to the Python binary, not to the AppImage.

---

## Building the AppImage

```bash
./build-appimage.sh
```

Produces `build/ThisMachine-x86_64.AppImage` — a self-contained, offline-capable
bundle. The script downloads a portable CPython
([python-build-standalone](https://github.com/astral-sh/python-build-standalone),
GLIBC 2.17+ so it runs on old distros), vendors xterm.js so no CDN is needed at
runtime, freezes everything with PyInstaller, and packs it with `appimagetool`.

Requires `curl`, `tar`, and FUSE. Everything it downloads lands in `build/` and
`vendor/`, both of which are gitignored — nothing fetched is checked in.

---

## Layout

The whole application is one file.

```
thismachine.py       Flask server + embedded HTML/CSS/JS (~2,600 lines)
start.sh             Run from source
build-appimage.sh    Build the release bundle
requirements.txt     flask, cryptography
```

---

## Security

ThisMachine executes shell commands as the user running it, with no
authentication. That is the point of the tool, and it is why it binds to
loopback only. Do not set `TERMSITE_HOST` to a non-loopback address, and do not
expose the port through a reverse proxy or tunnel — anyone who can reach it has
a shell on your machine. Also, this app has not been reviewed by a professional 
or anything, so it should not be used on any systems with sensitive data on 
them. It is mostly intended to help introduce the Linux command line in a 
somewhat temporary environment.

---

## License

MIT — see [LICENSE](LICENSE).
