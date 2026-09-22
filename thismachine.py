#!/usr/bin/env python3
"""Terminal Site — iMessage-style shell in a browser."""
import base64
import json
import os
import queue
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid

from flask import Flask, Response, request, jsonify, send_from_directory, redirect

# Base directory for bundled assets. Under PyInstaller the app is unpacked to a
# temp dir exposed as sys._MEIPASS; from source it's just this file's folder.
BASE_DIR   = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
VENDOR_DIR = os.path.join(BASE_DIR, "vendor")
HAS_VENDOR = os.path.exists(os.path.join(VENDOR_DIR, "xterm.min.js"))

try:
    import pty, select, fcntl, termios, struct
    HAS_PTY = True
except ImportError:
    HAS_PTY = False

# ── Config ────────────────────────────────────────────────────────────────────
HOST          = os.environ.get("TERMSITE_HOST", "127.0.0.1")
PORT          = int(os.environ.get("TERMSITE_PORT", "443"))

# *.localhost is resolved to 127.0.0.1 by Chrome (69+) and Firefox (75+)
# without DNS or /etc/hosts changes — RFC 6761 special-case.
# If thismachine.chat is in /etc/hosts (added by the setup wizard) we use that
# instead so the URL looks like a real domain with no port suffix.
def _detect_browser_host() -> str:
    if not os.environ.get("TERMSITE_BROWSER_HOST"):
        try:
            with open("/etc/hosts") as _f:
                if "thismachine.chat" in _f.read():
                    return "thismachine.chat"
        except OSError:
            pass
    return os.environ.get("TERMSITE_BROWSER_HOST", "thismachine.localhost")

BROWSER_HOST  = _detect_browser_host()
HOME_DIR      = os.path.expanduser("~")
HISTORY_FILE  = os.path.expanduser(
    os.environ.get("TERMSITE_HISTORY_FILE", "~/.termsite_history.json")
)
SETTINGS_FILE = os.path.expanduser("~/.termsite_settings.json")

# ── First-run setup config ────────────────────────────────────────────────────
_CONFIG_DIR = os.path.expanduser("~/.config/thismachine")
_SETUP_CFG  = os.path.join(_CONFIG_DIR, "setup.json")
_RUN_USER   = os.environ.get("USER") or os.environ.get("LOGNAME") or "user"
_APPIMAGE   = os.environ.get("APPIMAGE")                   # set by AppImage runtime
_EXEC_PATH  = _APPIMAGE or os.path.abspath(sys.argv[0])   # path for systemd ExecStart

def _read_setup_cfg() -> dict:
    try:
        with open(_SETUP_CFG) as _f:
            return json.load(_f)
    except Exception:
        return {}

def _write_setup_cfg(**kw) -> None:
    os.makedirs(_CONFIG_DIR, mode=0o755, exist_ok=True)
    cfg = _read_setup_cfg()
    cfg.update(kw)
    with open(_SETUP_CFG, "w") as _f:
        json.dump(cfg, _f)

def _should_show_setup() -> bool:
    """Whether to surface the install/setup wizard on launch.

    Shown on every start so the install option stays in front of the user —
    UNLESS they ticked "Don't ask again" (``never``) or the system service is
    already installed (``method == "admin"``), in which case there's nothing
    to prompt for. Install/uninstall remain reachable from Settings regardless."""
    cfg = _read_setup_cfg()
    if cfg.get("never"):
        return False
    if cfg.get("method") == "admin":
        return False
    return True

# ── TLS certificate ───────────────────────────────────────────────────────────
_CERT_DIR  = os.path.expanduser("~/.termsite_cert")
_CERT_FILE = os.path.join(_CERT_DIR, "thismachine.crt")
_KEY_FILE  = os.path.join(_CERT_DIR, "thismachine.key")

def _ensure_tls() -> "tuple[str|None, str|None, bool]":
    """Return (cert_path, key_path, is_new_cert).

    Prefers mkcert-signed certs (green padlock, no warning) when placed in
    ~/.termsite_cert/.  Falls back to an auto-generated self-signed cert.
    Returns (None, None, False) when neither is available."""
    # mkcert writes these names when you run: mkcert thismachine.localhost
    mc_crt = os.path.join(_CERT_DIR, "thismachine.localhost.pem")
    mc_key = os.path.join(_CERT_DIR, "thismachine.localhost-key.pem")
    if os.path.exists(mc_crt) and os.path.exists(mc_key):
        return mc_crt, mc_key, False

    if os.path.exists(_CERT_FILE) and os.path.exists(_KEY_FILE):
        # Regen if the cert pre-dates thismachine.chat SAN support.
        try:
            from cryptography import x509 as _cx
            with open(_CERT_FILE, "rb") as _f:
                _c = _cx.load_pem_x509_certificate(_f.read())
            _dns = _c.extensions.get_extension_for_class(
                _cx.SubjectAlternativeName).value.get_values_for_type(_cx.DNSName)
            if "thismachine.chat" not in _dns:
                os.unlink(_CERT_FILE); os.unlink(_KEY_FILE)
            else:
                return _CERT_FILE, _KEY_FILE, False
        except Exception:
            return _CERT_FILE, _KEY_FILE, False

    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import ipaddress as _ip, datetime as _dt
    except ImportError:
        return None, None, False

    try:
        os.makedirs(_CERT_DIR, mode=0o700, exist_ok=True)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(_KEY_FILE, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))
        os.chmod(_KEY_FILE, 0o600)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, BROWSER_HOST)])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject).issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_dt.datetime.utcnow())
            .not_valid_after(_dt.datetime.utcnow() + _dt.timedelta(days=3650))
            .add_extension(x509.SubjectAlternativeName([
                # Include all local domains upfront so the cert is valid regardless
                # of whether thismachine.chat has been configured in /etc/hosts yet.
                x509.DNSName("thismachine.localhost"),
                x509.DNSName("thismachine.chat"),
                x509.DNSName("localhost"),
                x509.IPAddress(_ip.IPv4Address("127.0.0.1")),
            ]), critical=False)
            .sign(key, hashes.SHA256())
        )
        with open(_CERT_FILE, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        return _CERT_FILE, _KEY_FILE, True
    except Exception as exc:
        print(f"[tls] cert generation failed: {exc}", file=sys.stderr)
        return None, None, False

# Idempotent after the first launch (cert already exists → fast path).
_TLS_CERT, _TLS_KEY, _TLS_NEW = _ensure_tls()

def _make_browser_url(host: str, port: int) -> str:
    """Build the URL shown to the user, omitting the port when it is the
    default for the scheme (443 for https, 80 for http) so the URL is clean."""
    scheme  = "https" if _TLS_CERT else "http"
    default = 443     if _TLS_CERT else 80
    return f"{scheme}://{host}" if port == default else f"{scheme}://{host}:{port}"

BROWSER_URL = _make_browser_url(BROWSER_HOST, PORT)

# ── State ─────────────────────────────────────────────────────────────────────
app      = Flask(__name__)
jobs      : dict[str, queue.Queue] = {}
job_state : dict[str, dict]        = {}   # job_id -> {master: int, pid: int}
sessions  : dict[str, dict]        = {}   # session_id -> {cwd: str}
hist_lock = threading.Lock()

# Strip everything EXCEPT SGR color/style codes (\x1b[...m).
# Cursor movement, screen-clear, OSC, and other non-color sequences are removed;
# color codes pass through so the client can render them as HTML.
_FILTER_RE = re.compile(
    r"\x1b(?:"
    r"[@-Z\\-_]"               # Non-CSI single-char ESC sequences (Fe)
    r"|\[[0-?]*[ -/]*[@-l]"    # CSI: final byte 0x40-0x6C (everything except 'm')
    r"|\[[0-?]*[ -/]*[n-~]"    # CSI: final byte 0x6E-0x7E (everything except 'm')
    r"|\][^\x07\x1b]*(?:\x07|\x1b\\)"  # OSC sequences (window title, etc.)
    r")"
)

def filter_ansi(text: str) -> str:
    """Strip non-color ANSI codes and normalise line endings from PTY."""
    return _FILTER_RE.sub("", text).replace("\r\n", "\n").replace("\r", "")

def _strip_noncolor(text: str) -> str:
    """Strip non-color ANSI codes but keep \\r so we can model overwrites."""
    return _FILTER_RE.sub("", text)

def linearize(text: str) -> str:
    """Turn raw PTY output into clean, replayable text for history storage.

    Keeps SGR color codes (the client renders them) but collapses carriage-return
    overwrites — e.g. a progress bar that rewrites its line keeps only the final
    frame instead of every intermediate one."""
    text = _strip_noncolor(text).replace("\r\n", "\n")
    return "\n".join(seg.split("\r")[-1] for seg in text.split("\n"))

# Detects "redraw" output that cannot be linearised into a scrollback log:
# alternate-screen apps (top, nano, less, vim) and in-place cursor repainting
# (claude code, spinners). Such commands store a short placeholder in history
# instead of thousands of unintelligible overlapping frames.
_INTERACTIVE_RE = re.compile(
    r"\x1b\[[0-9;]*[AHfJ]"          # cursor up / home / position / erase-display
    r"|\x1b\[\?(?:1049|1047|47)[hl]"  # alternate screen buffer
)
INTERACTIVE_PLACEHOLDER = "⟨ interactive session ⟩"

# Detect sudo password prompts so the client can show a native input dialog.
# Matches "[sudo] password for user: " and bare "Password: " at end of output.
_SUDO_PROMPT_RE = re.compile(
    r'(?:\[sudo\] )?[Pp]assword(?: for [^\n:]+)?:\s*\Z'
)
_SUDO_FAIL_RE = re.compile(r'Sorry,\s+try\s+again\.')

# Ephemeral Fernet key — generated fresh each server start, never written to disk.
# Password bytes are encrypted before being stored in the sessions dict so the
# plaintext is not sitting in readable memory as a Python str object.
try:
    from cryptography.fernet import Fernet as _Fernet
    _SUDO_FERNET = _Fernet(_Fernet.generate_key())
    def _enc_pwd(p: str) -> bytes: return _SUDO_FERNET.encrypt(p.encode())
    def _dec_pwd(b: bytes) -> str:  return _SUDO_FERNET.decrypt(b).decode()
except Exception:
    def _enc_pwd(p: str) -> bytes: return p.encode()          # fallback: no crypto
    def _dec_pwd(b: bytes) -> str:  return b.decode()

# Shell builtins/keywords offered alongside PATH executables for tab completion.
BUILTINS = sorted({
    "cd", "echo", "exit", "export", "alias", "unalias", "pwd", "pushd", "popd",
    "source", ".", "history", "kill", "jobs", "fg", "bg", "set", "unset",
    "read", "test", "type", "command", "time", "umask", "wait", "trap",
    "let", "local", "return", "declare", "eval", "exec", "shift", "printf",
})

# ── Settings ──────────────────────────────────────────────────────────────────
def load_settings() -> dict:
    try:
        with open(SETTINGS_FILE) as f:
            return json.load(f)
    except Exception:
        return {"max_history_mb": 10.0}

def persist_settings(s: dict) -> None:
    with open(SETTINGS_FILE, "w") as f:
        json.dump(s, f)

def max_history_bytes() -> int:
    mb = float(load_settings().get("max_history_mb", 10.0))
    return int(mb * 1024 * 1024)

# ── History ───────────────────────────────────────────────────────────────────
_MAX_ENTRY_BYTES = 64 * 1024

def load_history() -> list:
    try:
        with open(HISTORY_FILE) as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []

def append_history(cmd: str, output: str, code: int, ts: float) -> None:
    raw = output.encode()
    if len(raw) > _MAX_ENTRY_BYTES:
        output = raw[:_MAX_ENTRY_BYTES].decode(errors="replace") + "\n[truncated at 64 KB]"
    with hist_lock:
        history = load_history()
        history.append({"ts": ts, "cmd": cmd, "output": output, "code": code})
        cap  = max_history_bytes()
        blob = json.dumps(history, separators=(",", ":")).encode()
        while len(history) > 1 and len(blob) > cap:
            history = history[1:]
            blob = json.dumps(history, separators=(",", ":")).encode()
        try:
            with open(HISTORY_FILE, "w") as f:
                f.write(blob.decode())
        except OSError as exc:
            print(f"[history] {exc}")

# ── Sessions ──────────────────────────────────────────────────────────────────
def get_session(req) -> tuple[str, dict]:
    sid = req.headers.get("X-Session-Id") or str(uuid.uuid4())
    if sid not in sessions:
        sessions[sid] = {
            "cwd":      HOME_DIR,
            "pty":      SessionPTY() if HAS_PTY else None,
            "sudo_pwd": None,   # cached password (cleared after 5 min or on failure)
            "sudo_exp": 0.0,    # expiry timestamp
        }
    return sid, sessions[sid]

# ── Session PTY (shared across commands — preserves sudo timestamp) ───────────
class SessionPTY:
    """One master fd per browser session.  Every command reopens the same
    slave device (/dev/pts/N), so sudo sees the same TTY and honours its
    credential cache across consecutive commands."""

    def __init__(self) -> None:
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
        self.master     = master
        self.slave_path = os.ttyname(slave)
        os.close(slave)          # close; we'll reopen per-command

    def open_slave(self) -> int:
        return os.open(self.slave_path, os.O_RDWR | os.O_NOCTTY)

# ── PTY execution (Linux / macOS) ─────────────────────────────────────────────
def _setup_child_pty() -> None:
    """Run in child: new session so it owns the PTY and receives signals."""
    os.setsid()
    try:
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)   # stdin (slave fd) becomes ctty
    except Exception:
        pass

def _run_pty(command: str, session: dict, q: queue.Queue, job_id: str, ts: float,
             size: tuple[int, int] = (24, 80), sid: str = "") -> None:
    rows, cols = size
    cwd     = session.get("cwd", HOME_DIR)
    cwd_tmp = tempfile.mktemp(prefix=".termsite_cwd_")
    wrapped = f"{command}; __ec=$?; pwd > {shlex.quote(cwd_tmp)} 2>/dev/null; exit $__ec"

    sess_pty: SessionPTY = session["pty"]
    master = sess_pty.master
    # Resize the PTY to match the client's terminal so apps (top, nano, claude)
    # wrap at the right column and nothing is clipped.
    try:
        fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    except OSError:
        pass
    slave  = sess_pty.open_slave()   # same /dev/pts/N every time → sudo keeps timestamp

    # A correct TERM is essential — without it top/nano/less fall back to dumb
    # rendering. Advertise a full-featured terminal and the live size.
    env = os.environ.copy()
    env["TERM"]      = "xterm-256color"
    env["COLORTERM"] = "truecolor"
    env["COLUMNS"]   = str(cols)
    env["LINES"]     = str(rows)

    raw_all: list[str] = []
    code = 1
    try:
        proc = subprocess.Popen(
            ["bash", "-c", wrapped],
            stdin=slave, stdout=slave, stderr=slave,
            close_fds=True, cwd=cwd, env=env,
            preexec_fn=_setup_child_pty,
        )
        os.close(slave)
        # Update job_state (pre-populated with session_id in /run route).
        job_state.setdefault(job_id, {}).update({"master": master, "pid": proc.pid})

        buf = b""
        _sudo_wait = False   # True while waiting for the user to type a password
        while True:
            try:
                r, _, _ = select.select([master], [], [], 0.05)
            except (ValueError, OSError):
                break
            if r:
                try:
                    chunk = os.read(master, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
                try:
                    text = buf.decode("utf-8"); buf = b""
                except UnicodeDecodeError:
                    text = buf.decode("utf-8", errors="replace"); buf = b""
                if text:
                    raw_all.append(text)

                    # ── Sudo password handling ──────────────────────────────
                    # Check BEFORE queuing so we can suppress the prompt line
                    # from appearing in the terminal.
                    m_prompt = None if _sudo_wait else _SUDO_PROMPT_RE.search(text)

                    if m_prompt:
                        # Send any output that came before the prompt, then stop.
                        pre = text[:m_prompt.start()]
                        if pre:
                            q.put({"type": "output", "data": pre})
                        _sudo_wait = True
                        cached = None
                        if sid:
                            sess = sessions.get(sid, {})
                            enc = sess.get("sudo_pwd") if sess.get("sudo_exp", 0) > time.time() else None
                            if enc:
                                try:
                                    cached = _dec_pwd(enc)
                                except Exception:
                                    pass
                        if cached:
                            # Auto-fill silently — prompt text already suppressed.
                            # Leave _sudo_wait=True so the \r\n echo is swallowed too.
                            try:
                                os.write(master, (cached + "\r").encode())
                            except OSError:
                                pass
                        else:
                            q.put({"type": "sudo_prompt",
                                   "data": m_prompt.group(0)})
                    elif _sudo_wait and _SUDO_FAIL_RE.search(text):
                        # Wrong password — clear cache; suppress "Sorry, try again."
                        # The re-prompt will arrive in the next chunk.
                        _sudo_wait = False
                        if sid and sid in sessions:
                            sessions[sid]["sudo_pwd"] = None
                            sessions[sid]["sudo_exp"] = 0.0
                        # If the re-prompt is bundled in the same chunk, fire dialog now.
                        m2 = _SUDO_PROMPT_RE.search(text)
                        if m2:
                            _sudo_wait = True
                            q.put({"type": "sudo_prompt",
                                   "data": m2.group(0), "retry": True})
                    elif _sudo_wait:
                        # Still waiting (e.g. echoed newline after typing password);
                        # suppress until we get real output confirming sudo moved on.
                        if text.strip():
                            _sudo_wait = False
                            q.put({"type": "output", "data": text})
                    else:
                        q.put({"type": "output", "data": text})
            elif proc.poll() is not None:
                try:
                    while True:
                        r2, _, _ = select.select([master], [], [], 0.05)
                        if not r2: break
                        chunk = os.read(master, 65536)
                        if not chunk: break
                        raw = chunk.decode("utf-8", errors="replace")
                        if raw:
                            q.put({"type": "output", "data": raw})
                            raw_all.append(raw)
                except OSError:
                    pass
                break

        proc.wait()
        code = proc.returncode

    except Exception as exc:
        q.put({"type": "error", "data": str(exc)})
    finally:
        job_state.pop(job_id, None)
        # Do NOT close master — it belongs to the session (sudo TTY preservation)

    # Update session CWD
    new_cwd = cwd
    try:
        with open(cwd_tmp) as f:
            nc = f.read().strip()
        if nc: new_cwd = nc
        os.unlink(cwd_tmp)
    except OSError:
        pass
    session["cwd"] = new_cwd

    full = "".join(raw_all)
    interactive = bool(_INTERACTIVE_RE.search(full))

    q.put({"type": "cwd",  "path": new_cwd})
    q.put({"type": "exit", "code": code, "interactive": interactive})
    q.put(None)

    hist = INTERACTIVE_PLACEHOLDER if interactive else linearize(full)
    threading.Thread(target=append_history, args=(command, hist, code, ts), daemon=True).start()

# ── Fallback execution (no PTY) ───────────────────────────────────────────────
def _run_plain(command: str, session: dict, q: queue.Queue, job_id: str, ts: float,
               size: tuple[int, int] = (24, 80), sid: str = "") -> None:
    cwd     = session.get("cwd", HOME_DIR)
    cwd_tmp = tempfile.mktemp(prefix=".termsite_cwd_")
    wrapped = f"{command}; __ec=$?; pwd > {shlex.quote(cwd_tmp)} 2>/dev/null; exit $__ec"
    parts: list[str] = []
    code = 1
    try:
        proc = subprocess.Popen(
            ["bash", "-c", wrapped],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, close_fds=True, cwd=cwd,
        )
        for line in iter(proc.stdout.readline, ""):
            filtered = filter_ansi(line)
            parts.append(filtered)
            q.put({"type": "output", "data": filtered})
        proc.stdout.close()
        proc.wait()
        code = proc.returncode
    except Exception as exc:
        q.put({"type": "error", "data": str(exc)})

    new_cwd = cwd
    try:
        with open(cwd_tmp) as f:
            nc = f.read().strip()
        if nc: new_cwd = nc
        os.unlink(cwd_tmp)
    except OSError:
        pass
    session["cwd"] = new_cwd

    q.put({"type": "cwd",  "path": new_cwd})
    q.put({"type": "exit", "code": code})
    q.put(None)
    threading.Thread(target=append_history, args=(command, "".join(parts), code, ts), daemon=True).start()

_run_command = _run_pty if HAS_PTY else _run_plain

# ── HTML ──────────────────────────────────────────────────────────────────────
# __HOME__ is replaced at serve-time with the server's home directory.
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ThisMachine</title>
<link rel="manifest" href="/manifest.json">
<link rel="icon" href="/icon.svg" type="image/svg+xml">
<meta name="theme-color" content="#007AFF" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#000000" media="(prefers-color-scheme: dark)">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-title" content="ThisMachine">
<link  href="__XTERM_CSS__" rel="stylesheet">
<script src="__XTERM_JS__"></script>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --blue:       #007AFF;
    --green:      #34C759;
    --orange:     #FF9500;
    --gray-bg:    #F2F2F7;
    --bubble-in:  #E9E9EB;
    --bubble-out: #007AFF;
    --text-dark:  #000000;
    --text-light: #8E8E93;
    --separator:  rgba(60,60,67,0.18);
    --glass:      rgba(255,255,255,0.82);
    --red-bg:     #FFE5E5;
    --red-text:   #C0392B;
    --mono:       'SF Mono', ui-monospace, 'Menlo', 'Monaco', 'Courier New', monospace;
    --sans:       -apple-system, BlinkMacSystemFont, 'SF Pro Text', 'Helvetica Neue', sans-serif;
    --font-bubble: 15px;
    --font-mono:   13px;
    --ansi-dk:     #3a3a3a;
  }

  @media (prefers-color-scheme: dark) {
    :root {
      --gray-bg:   #000000;
      --bubble-in: #1C1C1E;
      --text-dark: #FFFFFF;
      --separator: rgba(255,255,255,0.15);
      --glass:     rgba(28,28,30,0.85);
      --red-bg:    #3A1010;
      --red-text:  #FF6B6B;
      --ansi-dk:   #cccccc;
    }
  }

  html, body { height: 100%; overflow: hidden; background: var(--gray-bg); font-family: var(--sans); color: var(--text-dark); }
  body { display: flex; flex-direction: column; }

  /* ── Header ── */
  header {
    background: var(--glass);
    backdrop-filter: blur(20px) saturate(180%);
    -webkit-backdrop-filter: blur(20px) saturate(180%);
    border-bottom: 0.5px solid var(--separator);
    padding: 10px 44px 8px;
    display: flex; flex-direction: column; align-items: center; gap: 2px;
    flex-shrink: 0; z-index: 10; position: relative;
  }
  .avatar {
    width: 40px; height: 40px; border-radius: 50%;
    background: linear-gradient(145deg, #007AFF 0%, #5856D6 100%);
    display: flex; align-items: center; justify-content: center;
    font-size: 14px; font-weight: 700; color: #fff; letter-spacing: -0.3px;
    margin-bottom: 3px; flex-shrink: 0; user-select: none;
    box-shadow: 0 2px 8px rgba(0,122,255,0.35);
  }
  .contact-name { font-size: 13px; font-weight: 600; color: var(--text-dark); letter-spacing: -0.2px; }
  .contact-cwd  { font-size: 11px; color: var(--green); font-family: var(--mono); max-width: 80vw; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

  #settings-btn {
    position: absolute; right: 12px; top: 50%; transform: translateY(-50%);
    background: none; border: none; color: var(--text-light); cursor: pointer;
    padding: 6px; border-radius: 8px; display: flex; align-items: center;
    transition: color 0.15s;
  }
  #settings-btn:hover { color: var(--text-dark); }

  /* ── Messages ── */
  #messages {
    flex: 1; overflow-y: auto; padding: 16px 10px 8px;
    display: flex; flex-direction: column; gap: 2px; overscroll-behavior: contain;
  }
  #messages::-webkit-scrollbar { width: 3px; }
  #messages::-webkit-scrollbar-thumb { background: var(--separator); border-radius: 2px; }

  .timestamp { font-size: 11px; color: var(--text-light); text-align: center; margin: 10px 0 4px; }

  .row { display: flex; align-items: flex-end; gap: 6px; }
  .row.out { justify-content: flex-end; }
  .row.in  { justify-content: flex-start; }

  .bubble { max-width: 78%; padding: 8px 13px; border-radius: 18px; font-size: var(--font-bubble); line-height: 1.4; word-break: break-word; }
  .bubble.out { background: var(--bubble-out); color: #fff; border-bottom-right-radius: 4px; }
  .bubble.in  {
    background: var(--bubble-in); color: var(--text-dark); border-bottom-left-radius: 4px;
    font-family: var(--mono); font-size: var(--font-mono); white-space: pre-wrap; max-width: 88%; overflow-x: auto;
  }
  .bubble.in.err { background: var(--red-bg); color: var(--red-text); }

  /* ── xterm.js output bubble ── */
  .term-bubble {
    border-radius: 18px;
    border-bottom-left-radius: 4px;
    overflow: hidden;
    width: fit-content;
    max-width: 94vw;   /* terminal is sized in JS to fit; this is just a safety cap */
    flex-shrink: 0;
  }
  /* xterm.js internal padding */
  .term-bubble .xterm { padding: 6px 8px 4px; }
  /* Terminals grow to fit their output so the page scrolls, not the bubble.
     If output is huge and an inner scrollbar is still needed, make it visible. */
  .term-bubble .xterm-viewport::-webkit-scrollbar { width: 9px; }
  .term-bubble .xterm-viewport::-webkit-scrollbar-thumb {
    background: var(--text-light); border-radius: 5px; border: 2px solid transparent; background-clip: padding-box;
  }
  /* Static snapshot of finished command output — replaces the live terminal so
     there is never an inner scrollbar or stray cursor. Font matches xterm.js
     exactly so the measured column count fits without horizontal scrolling. */
  .bubble.in.term-static {
    white-space: pre; overflow-x: auto; max-width: 94vw;
    padding: 8px 11px;
    font-family: 'SF Mono','Menlo','Monaco','Courier New',monospace;
    font-size: var(--font-mono); line-height: 1.25;
  }
  .bubble.in.term-static::-webkit-scrollbar { height: 9px; }
  .bubble.in.term-static::-webkit-scrollbar-thumb {
    background: var(--text-light); border-radius: 5px; border: 2px solid transparent; background-clip: padding-box;
  }
  /* Exit-code annotation shown below the terminal */
  .term-exit-note {
    padding: 1px 10px 5px; font-size: 11px;
    font-family: var(--mono); opacity: 0.75;
  }
  .term-exit-note.err { color: var(--red-text); }

  /* ── Thinking dots ── */
  .thinking { background: var(--bubble-in); border-radius: 18px; border-bottom-left-radius: 4px; padding: 11px 14px; display: flex; align-items: center; gap: 5px; width: fit-content; }
  .dot { width: 7px; height: 7px; border-radius: 50%; background: var(--text-light); animation: pulse 1.5s ease-in-out infinite; opacity: 0.4; }
  .dot:nth-child(1) { animation-delay: 0.0s; }
  .dot:nth-child(2) { animation-delay: 0.2s; }
  .dot:nth-child(3) { animation-delay: 0.4s; }
  @keyframes pulse { 0%,100% { transform: translateY(0); opacity: 0.4; } 35% { transform: translateY(-7px); opacity: 1; } }

  /* ── Input bar ── */
  #bar { background: var(--glass); backdrop-filter: blur(20px) saturate(180%); -webkit-backdrop-filter: blur(20px) saturate(180%); border-top: 0.5px solid var(--separator); padding: 8px 10px 10px; display: flex; align-items: center; gap: 8px; flex-shrink: 0; }

  #cmd {
    flex: 1; font-family: var(--mono); font-size: var(--font-mono); color: var(--text-dark);
    background: var(--gray-bg); border: 1.5px solid var(--separator); border-radius: 22px;
    padding: 8px 15px; outline: none; transition: border-color 0.15s; min-width: 0;
  }
  #cmd::placeholder { font-family: var(--sans); color: var(--text-light); font-size: var(--font-mono); }
  #cmd:focus { border-color: var(--blue); }
  #cmd.raw-mode { border-color: var(--orange); color: var(--text-light); font-family: var(--sans); font-style: italic; }

  #send { width: 33px; height: 33px; border-radius: 50%; border: none; background: var(--blue); color: #fff; cursor: pointer; display: flex; align-items: center; justify-content: center; flex-shrink: 0; transition: opacity 0.15s, transform 0.1s; }
  #send:hover { opacity: 0.85; } #send:active { transform: scale(0.90); } #send:disabled { background: var(--text-light); cursor: default; }

  /* ── Settings overlay ── */
  .overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.45); display: flex; align-items: center; justify-content: center; z-index: 100; opacity: 0; pointer-events: none; transition: opacity 0.2s; }
  .overlay.open { opacity: 1; pointer-events: auto; }

  .modal { background: var(--glass); backdrop-filter: blur(30px) saturate(200%); -webkit-backdrop-filter: blur(30px) saturate(200%); border-radius: 18px; padding: 24px 22px; width: min(360px, 92vw); display: flex; flex-direction: column; gap: 20px; box-shadow: 0 24px 60px rgba(0,0,0,0.35); }
  .modal-title { font-size: 17px; font-weight: 600; text-align: center; }

  .setting-group { display: flex; flex-direction: column; gap: 8px; }
  .setting-label { font-size: 13px; color: var(--text-light); font-weight: 500; }
  .setting-label strong { color: var(--text-dark); }

  input[type=range] { width: 100%; accent-color: var(--blue); cursor: pointer; }

  .num-row { display: flex; align-items: center; gap: 8px; }
  .num-row input[type=number] { flex: 1; padding: 8px 12px; border: 1.5px solid var(--separator); border-radius: 10px; font-size: 14px; background: var(--gray-bg); color: var(--text-dark); outline: none; }
  .num-row input[type=number]:focus { border-color: var(--blue); }
  .num-row span { font-size: 13px; color: var(--text-light); white-space: nowrap; }

  .modal-btns { display: flex; gap: 8px; }
  .mbtn { flex: 1; padding: 11px; border-radius: 12px; font-size: 15px; font-weight: 500; border: none; cursor: pointer; transition: opacity 0.15s; }
  .mbtn:hover { opacity: 0.85; }
  .mbtn-pri { background: var(--blue); color: #fff; }
  .mbtn-sec { background: var(--bubble-in); color: var(--text-dark); }
  .mbtn-red { background: #FF3B30; color: #fff; width: 100%; }

  /* ── Sudo password dialog ── */
  #sudo-pwd-wrap { position: relative; display: flex; align-items: center; }
  #sudo-pwd-display {
    flex: 1; padding: 10px 44px 10px 14px;
    border: 1.5px solid var(--blue); border-radius: 12px;
    font-size: 20px; background: var(--gray-bg); color: var(--text-dark);
    min-height: 42px; display: flex; align-items: center;
    letter-spacing: 4px; cursor: default; user-select: none;
  }
  .sudo-pwd-cursor {
    display: inline-block; width: 2px; height: 0.85em;
    background: var(--blue); vertical-align: middle;
    margin-left: 2px; animation: sudoBlink 1s step-end infinite;
  }
  @keyframes sudoBlink { 0%,100%{opacity:1} 50%{opacity:0} }
  @keyframes sudoShake {
    0%,100%{transform:translateX(0)} 20%{transform:translateX(-6px)}
    40%{transform:translateX(6px)}   60%{transform:translateX(-4px)}
    80%{transform:translateX(4px)}
  }
  .sudo-error { color: #FF3B30; font-size: 12px; text-align: center; margin-top: -6px; }
  #sudo-overlay .modal.sudo-shake { animation: sudoShake 0.35s ease; }
  #sudo-eye {
    position: absolute; right: 10px; background: none; border: none;
    cursor: pointer; color: var(--text-light); padding: 4px; display: flex;
    align-items: center; transition: color 0.15s;
  }
  #sudo-eye:hover { color: var(--text-dark); }
  .sudo-prompt-label {
    font-size: 13px; color: var(--text-light); text-align: center;
    font-family: var(--mono); word-break: break-all;
  }

  /* ── Tab-completion popup ── */
  #compbox {
    position: fixed; left: 10px; right: 10px; bottom: 58px;
    background: var(--glass); backdrop-filter: blur(20px) saturate(180%);
    -webkit-backdrop-filter: blur(20px) saturate(180%);
    border: 0.5px solid var(--separator); border-radius: 14px;
    padding: 8px 10px; display: none; flex-wrap: wrap; gap: 4px 14px;
    max-height: 38vh; overflow-y: auto; z-index: 90;
    box-shadow: 0 8px 28px rgba(0,0,0,0.28);
  }
  #compbox.show { display: flex; }
  .compitem {
    font-family: var(--mono); font-size: var(--font-mono); color: var(--text-dark);
    padding: 2px 7px; border-radius: 7px; cursor: pointer; white-space: nowrap;
  }
  .compitem:hover { background: var(--blue); color: #fff; }

  #toast {
    position: fixed; bottom: 80px; left: 50%;
    transform: translateX(-50%) translateY(16px);
    background: rgba(0,0,0,0.72); color: #fff;
    padding: 8px 18px; border-radius: 20px; font-size: 13px;
    opacity: 0; transition: opacity 0.2s, transform 0.2s;
    pointer-events: none; z-index: 200;
  }
  #toast.show { opacity: 1; transform: translateX(-50%) translateY(0); }
</style>
</head>
<body>

<header>
  <div class="avatar">TM</div>
  <div class="contact-name">ThisMachine</div>
  <div class="contact-cwd" id="cwd-display">__HOME__</div>
  <button id="settings-btn" title="Settings" onclick="openSettings()">
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <circle cx="12" cy="12" r="3"/>
      <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
    </svg>
  </button>
</header>

<div id="messages"></div>

<div id="bar">
  <input id="cmd" type="text" placeholder="Message"
         autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"/>
  <button id="send" onclick="sendCmd()">
    <svg width="15" height="15" viewBox="0 0 15 15" fill="none">
      <path d="M7.5 13V2M7.5 2L3 6.5M7.5 2L12 6.5" stroke="white" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>
  </button>
</div>

<!-- Settings modal -->
<div id="settings-overlay" class="overlay" onclick="closeSettings()">
  <div class="modal" onclick="event.stopPropagation()">
    <div class="modal-title">Settings</div>

    <div class="setting-group">
      <div class="setting-label">Font Size — <strong id="font-display">15</strong> px</div>
      <input type="range" id="font-slider" min="10" max="24" step="1" value="15"
             oninput="previewFont(this.value)">
    </div>

    <div class="setting-group">
      <div class="setting-label">Max History File Size</div>
      <div class="num-row">
        <input type="number" id="hist-mb" min="0.1" max="100000" step="0.1" value="10">
        <span>MB</span>
      </div>
    </div>

    <div class="setting-group" style="border-top:0.5px solid var(--separator);padding-top:16px;margin-top:4px">
      <div class="setting-label">Data</div>
      <button class="mbtn mbtn-red" onclick="clearHistory()">Clear History File</button>
    </div>

    <div class="setting-group" style="border-top:0.5px solid var(--separator);padding-top:16px;margin-top:4px">
      <div class="setting-label">System</div>
      <button class="mbtn mbtn-red" onclick="shutdownServer()">Shut Down Server</button>
    </div>

    <div id="setup-section" class="setting-group" style="display:none;border-top:0.5px solid var(--separator);padding-top:16px;margin-top:4px">
      <div class="setting-label">System Setup — <span id="setup-mode-label" style="color:var(--text-light);font-weight:400"></span></div>
      <div id="uninstall-confirm" style="display:none;background:rgba(255,59,48,.08);border-radius:10px;padding:12px;margin-bottom:8px;font-size:13px;color:var(--text-dark);line-height:1.6">
        <div id="uninstall-confirm-body">
          This will:<br>
          &bull;&nbsp;Remove <code>thismachine.chat</code> from <code>/etc/hosts</code><br>
          &bull;&nbsp;Stop and delete the <code>thismachine</code> systemd service<br>
          <span style="color:var(--text-light)">After restart, the server returns to <code>thismachine.localhost:5000</code>.</span>
          <div class="modal-btns" style="margin-top:12px">
            <button class="mbtn mbtn-sec" onclick="hideUninstallConfirm()">Cancel</button>
            <button class="mbtn mbtn-red" onclick="runUninstall()">Confirm Uninstall</button>
          </div>
        </div>
      </div>
      <button id="install-btn" class="mbtn mbtn-pri" style="display:none" onclick="goInstall()">Set Up System Service…</button>
      <button id="uninstall-btn" class="mbtn mbtn-red" style="display:none" onclick="showUninstallConfirm()">Uninstall System Setup</button>
    </div>

    <div class="modal-btns">
      <button class="mbtn mbtn-sec" onclick="closeSettings()">Cancel</button>
      <button class="mbtn mbtn-pri" onclick="saveSettings()">Save</button>
    </div>
  </div>
</div>

<!-- Sudo password dialog -->
<div id="sudo-overlay" class="overlay" onclick="cancelSudo(event)">
  <div class="modal" onclick="event.stopPropagation()" style="gap:16px">
    <div style="display:flex;flex-direction:column;align-items:center;gap:6px">
      <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="var(--blue)"
           stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
        <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
        <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
      </svg>
      <div class="modal-title" style="font-size:15px">Authentication Required</div>
    </div>
    <div id="sudo-prompt-label" class="sudo-prompt-label"></div>
    <div id="sudo-pwd-wrap">
      <div id="sudo-pwd-display"><span id="sudo-dots"></span><span class="sudo-pwd-cursor"></span></div>
      <button id="sudo-eye" onclick="toggleSudoEye()" title="Show / hide password">
        <svg id="sudo-eye-icon" width="18" height="18" viewBox="0 0 24 24" fill="none"
             stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>
        </svg>
      </button>
    </div>
    <div class="modal-btns">
      <button class="mbtn mbtn-sec" onclick="cancelSudo()">Cancel</button>
      <button class="mbtn mbtn-pri" onclick="submitSudoPwd()">Authenticate</button>
    </div>
  </div>
</div>

<div id="toast"></div>

<script>
// ── Session ID (per browser tab, resets on close) ────────────────────────────
const SESSION_ID = (() => {
  let id = sessionStorage.getItem('termsite_sid');
  if (!id) { id = crypto.randomUUID(); sessionStorage.setItem('termsite_sid', id); }
  return id;
})();

function api(url, opts = {}) {
  return fetch(url, { ...opts, headers: { 'X-Session-Id': SESSION_ID, ...(opts.headers || {}) } });
}

// ── Font size (persisted in localStorage) ────────────────────────────────────
let currentFontSize = parseInt(localStorage.getItem('termsite_font') || '15');
function applyFont(n) {
  document.documentElement.style.setProperty('--font-bubble', n + 'px');
  document.documentElement.style.setProperty('--font-mono',   (n - 2) + 'px');
}
applyFont(currentFontSize);

// ── DOM refs ─────────────────────────────────────────────────────────────────
const feed    = document.getElementById('messages');
const input   = document.getElementById('cmd');
const btn     = document.getElementById('send');
const cwdEl   = document.getElementById('cwd-display');

// ── Timestamp windowing (5-minute window) ────────────────────────────────────
const TS_GAP = 5 * 60 * 1000;
let lastShownTs = null;

function maybeTimestamp(epochMs) {
  if (lastShownTs === null || epochMs - lastShownTs >= TS_GAP) {
    const el = document.createElement('div');
    el.className = 'timestamp';
    el.textContent = new Date(epochMs).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
    feed.appendChild(el);
    lastShownTs = epochMs;
  }
}

const scroll = () => feed.scrollTop = feed.scrollHeight;

function outBubble(text) {
  const row = document.createElement('div'); row.className = 'row out';
  const b   = document.createElement('div'); b.className = 'bubble out'; b.textContent = text;
  row.appendChild(b); feed.appendChild(row); scroll();
}

function thinkingRow() {
  const row = document.createElement('div'); row.className = 'row in'; row.id = 'thinking';
  const t   = document.createElement('div'); t.className = 'thinking';
  t.innerHTML = '<div class="dot"></div><div class="dot"></div><div class="dot"></div>';
  row.appendChild(t); feed.appendChild(row); scroll();
}
function removeThinking() { document.getElementById('thinking')?.remove(); }

function inBubble(isErr) {
  const row = document.createElement('div'); row.className = 'row in';
  const b   = document.createElement('div'); b.className = 'bubble in' + (isErr ? ' err' : '');
  row.appendChild(b); feed.appendChild(row); scroll();
  return b;
}

function clearScreen() {
  feed.innerHTML = '';   // remove every message bubble
  lastShownTs = null;    // restart the 5-minute timestamp window
  input.focus();
}

// Create an xterm.js terminal inside a bubble, inserted ABOVE the thinking dots.
// Sized to fit the viewport so wide apps (claude, top) aren't clipped on the right.
const TERM_FONT = "'SF Mono','Menlo','Monaco','Courier New',monospace";

// Measure the REAL advance width of the monospace font in the browser, so the
// column count we hand to the PTY/xterm.js actually fits the bubble — no right-
// edge clipping, no horizontal scrollbar on the static snapshot.
const _charWCache = {};
function measureCharW(fontSizePx) {
  if (_charWCache[fontSizePx]) return _charWCache[fontSizePx];
  const span = document.createElement('span');
  span.style.cssText = `position:absolute;visibility:hidden;white-space:pre;`
    + `font-family:${TERM_FONT};font-size:${fontSizePx}px`;
  span.textContent = '0'.repeat(100);
  document.body.appendChild(span);
  const w = span.getBoundingClientRect().width / 100;
  span.remove();
  return (_charWCache[fontSizePx] = w || fontSizePx * 0.6);
}

function computeTermSize() {
  const monoSz = parseInt(getComputedStyle(document.documentElement)
                          .getPropertyValue('--font-mono')) || 13;
  const charW = measureCharW(monoSz);
  const lineH = monoSz * 1.25;      // matches Terminal lineHeight below
  // Leave room for bubble padding (~22px) and a hair of safety so we never
  // round up past the available width.
  const availW = Math.min(window.innerWidth * 0.94, window.innerWidth - 16) - 24;
  const availH = (feed.clientHeight || window.innerHeight) * 0.72;
  const cols = Math.max(20, Math.min(Math.floor(availW / charW), 240));
  const rows = Math.max(8,  Math.min(Math.floor(availH / lineH), 50));
  return { cols, rows };
}

function createTermBubble(cols, rows) {
  const row  = document.createElement('div'); row.className = 'row in';
  const wrap = document.createElement('div'); wrap.className = 'term-bubble';
  row.appendChild(wrap);
  const thinking = document.getElementById('thinking');
  if (thinking) feed.insertBefore(row, thinking); else feed.appendChild(row);

  const dark   = window.matchMedia('(prefers-color-scheme: dark)').matches;
  const monoSz = parseInt(getComputedStyle(document.documentElement)
                          .getPropertyValue('--font-mono')) || 13;
  const term = new Terminal({
    cols, rows,
    fontFamily: "'SF Mono','Menlo','Monaco','Courier New',monospace",
    fontSize: monoSz, lineHeight: 1.25,
    disableStdin: true, scrollback: 2000, convertEol: false,
    allowTransparency: false,
    theme: {
      background:      dark ? '#1C1C1E' : '#E9E9EB',
      foreground:      dark ? '#e0e0e0' : '#1a1a1a',
      cursor:          '#007AFF', cursorAccent: '#ffffff',
      selectionBackground: 'rgba(0,122,255,0.28)',
      black:'#000000',        red:'#c0392b',    green:'#27ae60',  yellow:'#d4a017',
      blue:'#2980b9',         magenta:'#8e44ad',cyan:'#1a7a6e',   white:'#c7c7c7',
      brightBlack:'#7f8c8d',  brightRed:'#e74c3c',  brightGreen:'#2ecc71',
      brightYellow:'#f1c40f', brightBlue:'#3498db',  brightMagenta:'#9b59b6',
      brightCyan:'#1abc9c',   brightWhite:'#ffffff',
    },
  });
  term.open(wrap);
  scroll();
  return { term, wrap, row };
}

const DARK = window.matchMedia('(prefers-color-scheme: dark)').matches;

// After a normal command ends, resize the terminal so ALL its output is visible
// inline — the page scrolls, never a hidden scrollbar inside the bubble.
// Short commands collapse to a couple of rows; long ones grow (capped) to fit.
const MAX_FIT_ROWS = 1000;
function fitTermToContent(term) {
  const buf = term.buffer.active;
  let lastUsed = -1;
  for (let i = buf.length - 1; i >= 0; i--) {
    const ln = buf.getLine(i);
    if (ln && ln.translateToString(true).trim()) { lastUsed = i; break; }
  }
  const target = Math.max(1, Math.min(lastUsed + 1, MAX_FIT_ROWS));
  if (target !== term.rows) term.resize(term.cols, target);
  term.scrollToTop();
  scroll();
}

// ── Final-screen snapshot for interactive apps ───────────────────────────────
// xterm.js 256-colour palette → CSS (first 16 mirror our theme).
const PALETTE16 = ['#000000','#c0392b','#27ae60','#d4a017','#2980b9','#8e44ad',
                   '#1a7a6e','#c7c7c7','#7f8c8d','#e74c3c','#2ecc71','#f1c40f',
                   '#3498db','#9b59b6','#1abc9c','#ffffff'];
function xtermColor(idx) {
  if (idx < 16) return PALETTE16[idx];
  if (idx < 232) {
    idx -= 16;
    const lvl = v => v ? v * 40 + 55 : 0;
    return `rgb(${lvl((idx/36)|0)},${lvl(((idx%36)/6)|0)},${lvl(idx%6)})`;
  }
  const v = (idx - 232) * 10 + 8;
  return `rgb(${v},${v},${v})`;
}
function cellColor(cell, fg) {
  if (fg ? cell.isFgDefault() : cell.isBgDefault()) return null;
  const val = fg ? cell.getFgColor() : cell.getBgColor();
  if (fg ? cell.isFgRGB() : cell.isBgRGB()) return '#' + (val & 0xffffff).toString(16).padStart(6, '0');
  return xtermColor(val);
}
const escHtml = s => s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

function renderBufferLine(line, cols) {
  // Find the last meaningful column (non-space char OR a coloured background)
  // so trailing blank cells don't pad every line out to full width.
  let lastCol = -1;
  for (let x = cols - 1; x >= 0; x--) {
    const c = line.getCell(x);
    if (!c) continue;
    const ch = c.getChars();
    if ((ch && ch !== ' ') || !c.isBgDefault()) { lastCol = x; break; }
  }
  if (lastCol < 0) return { html: '', blank: true };

  let html = '', open = false, curKey = null;
  const close = () => { if (open) { html += '</span>'; open = false; } };
  for (let x = 0; x <= lastCol; x++) {
    const cell = line.getCell(x);
    if (!cell) { html += ' '; continue; }
    if (cell.getWidth() === 0) continue;       // second half of a wide glyph
    const ch = cell.getChars() || ' ';
    let fg = cellColor(cell, true), bg = cellColor(cell, false);
    if (cell.isInverse()) { const t = fg; fg = bg || (DARK?'#1C1C1E':'#E9E9EB'); bg = t || (DARK?'#e0e0e0':'#1a1a1a'); }
    const bold = cell.isBold(), italic = cell.isItalic(), under = cell.isUnderline();
    const key = fg+'|'+bg+'|'+bold+'|'+italic+'|'+under;
    if (key !== curKey) {
      close();
      const css = [];
      if (fg) css.push('color:'+fg);
      if (bg) css.push('background:'+bg);
      if (bold) css.push('font-weight:700');
      if (italic) css.push('font-style:italic');
      if (under) css.push('text-decoration:underline');
      if (css.length) { html += '<span style="'+css.join(';')+'">'; open = true; }
      curKey = key;
    }
    html += escHtml(ch);
  }
  close();
  return { html, blank: false };
}

// Freeze finished terminal output into styled HTML.
//   finalScreenOnly=true  → just the visible screen (interactive apps' last frame)
//   finalScreenOnly=false → the whole buffer incl. scrollback (normal commands)
// Trailing blank lines are dropped. The result replaces the live terminal so
// there is no cursor and no inner scrollbar — long output flows into the page.
function snapshotTerminal(term, finalScreenOnly) {
  const buf = term.buffer.active, cols = term.cols;
  const start = finalScreenOnly ? buf.baseY : 0;
  const end   = finalScreenOnly ? buf.baseY + term.rows : buf.length;
  const lines = [];
  for (let y = start; y < end; y++) {
    const ln = buf.getLine(y);
    lines.push(ln ? renderBufferLine(ln, cols) : { html: '', blank: true });
  }
  while (lines.length && lines[lines.length - 1].blank) lines.pop();
  return lines.map(l => l.html).join('\n');
}

// ── ANSI color → HTML ────────────────────────────────────────────────────────
// The server passes through SGR color codes; we convert them to styled spans.
function ansiToHtml(raw) {
  if (!raw) return '';
  const FG = {
    30:'var(--ansi-dk)', 31:'#c0392b',  32:'#27ae60',  33:'#d4a017',
    34:'#2980b9',        35:'#8e44ad',  36:'#1a7a6e',  37:'var(--text-dark)',
    39: null,
    90:'#7f8c8d', 91:'#e74c3c', 92:'#2ecc71', 93:'#f1c40f',
    94:'#3498db', 95:'#9b59b6', 96:'#1abc9c', 97:'var(--text-dark)',
  };
  const BG = {
    40:'#000', 41:'#c0392b', 42:'#27ae60', 43:'#d4a017',
    44:'#2980b9', 45:'#8e44ad', 46:'#1a7a6e', 47:'#ccc', 49: null,
  };
  const esc = s => s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

  let fg=null,bg=null,bold=false,italic=false,under=false;
  let out='', last=0;

  function flush(seg) {
    if (!seg) return;
    const css=[];
    if(fg)    css.push(`color:${fg}`);
    if(bg)    css.push(`background:${bg}`);
    if(bold)  css.push('font-weight:700');
    if(italic)css.push('font-style:italic');
    if(under) css.push('text-decoration:underline');
    const e = esc(seg);
    out += css.length ? `<span style="${css.join(';')}">${e}</span>` : e;
  }

  for (const m of raw.matchAll(/\x1b\[([0-9;]*)m/g)) {
    flush(raw.slice(last, m.index));
    last = m.index + m[0].length;
    const codes = m[1].length ? m[1].split(';').map(Number) : [0];
    for (const c of codes) {
      if(c===0)  { fg=null; bg=null; bold=false; italic=false; under=false; }
      else if(c===1)  bold=true;
      else if(c===3)  italic=true;
      else if(c===4)  under=true;
      else if(c===22) bold=false;
      else if(c===23) italic=false;
      else if(c===24) under=false;
      else if(FG[c]!==undefined) fg=FG[c];
      else if(BG[c]!==undefined) bg=BG[c];
    }
  }
  flush(raw.slice(last));
  return out;
}

// ── Sudo password dialog ─────────────────────────────────────────────────────
let _sudoJobId   = null;
let _sudoOpen    = false;   // read by rawKeyHandler to intercept keystrokes
let _sudoBuf     = '';      // password characters collected by rawKeyHandler
let _sudoShowPwd = false;   // eye-toggle: show plaintext vs dots

function _sudoRender() {
  document.getElementById('sudo-dots').textContent =
    _sudoShowPwd ? _sudoBuf : '•'.repeat(_sudoBuf.length);
}

function showSudoDialog(jobId, promptText, retry = false) {
  _sudoJobId   = jobId;
  _sudoBuf     = '';
  _sudoShowPwd = false;
  _sudoOpen    = true;
  document.getElementById('sudo-prompt-label').textContent = promptText.trim() || '[sudo] password:';
  document.getElementById('sudo-eye-icon').innerHTML =
    '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>';
  _sudoRender();
  // Show or clear the "incorrect password" error line
  let errEl = document.getElementById('sudo-err');
  if (retry) {
    if (!errEl) {
      errEl = document.createElement('div');
      errEl.id = 'sudo-err';
      errEl.className = 'sudo-error';
      errEl.textContent = 'Incorrect password — try again';
      document.getElementById('sudo-pwd-wrap').insertAdjacentElement('afterend', errEl);
    }
    // Shake the modal to signal failure
    const modal = document.querySelector('#sudo-overlay .modal');
    modal.classList.remove('sudo-shake');
    void modal.offsetWidth;  // reflow to restart animation
    modal.classList.add('sudo-shake');
    modal.addEventListener('animationend', () => modal.classList.remove('sudo-shake'), { once: true });
  } else {
    errEl?.remove();
  }
  document.getElementById('sudo-overlay').classList.add('open');
}

function hideSudoDialog() {
  _sudoOpen  = false;
  _sudoJobId = null;
  _sudoBuf   = '';
  document.getElementById('sudo-overlay').classList.remove('open');
  _sudoRender();
}

function toggleSudoEye() {
  _sudoShowPwd = !_sudoShowPwd;
  _sudoRender();
  document.getElementById('sudo-eye-icon').innerHTML = _sudoShowPwd
    ? '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>'
    : '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>';
}

async function submitSudoPwd() {
  const pwd   = _sudoBuf;
  const jobId = _sudoJobId;
  hideSudoDialog();
  if (!jobId) return;
  try {
    await api(`/sudo-auth/${jobId}`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({password: pwd}),
    });
  } catch (_) {}
}

function cancelSudo(e) {
  // If called from overlay background click, only cancel if click was on overlay itself.
  if (e && e.target !== document.getElementById('sudo-overlay')) return;
  hideSudoDialog();
  sendInput('\x03');  // Ctrl+C — cancel the blocked sudo prompt
}

function showToast(msg, ms = 2200) {
  const t = document.getElementById('toast');
  t.textContent = msg; t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), ms);
}

function sessionEnded(msg) {
  // Try the fast path first; browsers often block this for user-opened tabs.
  window.close();
  // Fallback: replace the page with a "session ended" screen after a short
  // delay so any pending xterm.js callbacks have time to flush.
  setTimeout(() => {
    document.body.innerHTML = `
      <div style="height:100vh;display:flex;flex-direction:column;align-items:center;
        justify-content:center;background:var(--gray-bg);color:var(--text-dark);
        font-family:var(--sans);gap:16px;text-align:center;padding:24px">
        <div style="width:56px;height:56px;border-radius:50%;
          background:linear-gradient(145deg,#007AFF 0%,#5856D6 100%);
          display:flex;align-items:center;justify-content:center;
          font-size:20px;font-weight:700;color:#fff;letter-spacing:-0.3px;
          box-shadow:0 2px 8px rgba(0,122,255,0.35)">TM</div>
        <div style="font-size:17px;font-weight:600">${msg || 'Session ended'}</div>
        <div style="font-size:13px;color:var(--text-light)">You may close this tab.</div>
        <button onclick="window.close()"
          style="margin-top:8px;padding:11px 28px;border-radius:12px;font-size:15px;
            font-weight:500;border:none;cursor:pointer;background:#007AFF;color:#fff">
          Close Tab
        </button>
      </div>`;
  }, 80);
}

async function shutdownServer() {
  if (!confirm('Shut down the ThisMachine server?\n\nAll open tabs will stop working.')) return;
  closeSettings();
  try { await api('/shutdown', { method: 'POST' }); } catch (_) {}
  sessionEnded('Server shut down');
}

// ── Command history navigation ────────────────────────────────────────────────
let cmdHistory = [];   // ordered oldest→newest
let histIdx    = -1;   // -1 = new command; 0 = most recent; 1 = second most recent …
let histDraft  = '';   // saved input text while navigating

function historyUp() {
  if (cmdHistory.length === 0) return;
  if (histIdx === -1) histDraft = input.value;
  histIdx = Math.min(histIdx + 1, cmdHistory.length - 1);
  input.value = cmdHistory[cmdHistory.length - 1 - histIdx];
  requestAnimationFrame(() => input.setSelectionRange(input.value.length, input.value.length));
}

function historyDown() {
  if (histIdx === -1) return;
  histIdx--;
  input.value = histIdx === -1 ? histDraft : cmdHistory[cmdHistory.length - 1 - histIdx];
  requestAnimationFrame(() => input.setSelectionRange(input.value.length, input.value.length));
}

function renderEntry(entry) {
  const isErr = entry.code !== 0;
  if (!entry.output || entry.output.length === 0) {
    // Successful, no output → render nothing (just the sent command stands).
    if (isErr) inBubble(true).textContent = `Exited with code ${entry.code}`;
    return;
  }
  const b = inBubble(isErr);
  b.innerHTML = ansiToHtml(entry.output + (isErr ? `\n[exited ${entry.code}]` : ''));
}

// ── History load ─────────────────────────────────────────────────────────────
async function loadHistory() {
  try {
    const entries = await api('/history').then(r => r.json());
    for (const e of entries) {
      // Deduplicate consecutive identical commands in history (like bash HISTCONTROL=ignoredups)
      if (e.cmd && (cmdHistory.length === 0 || cmdHistory[cmdHistory.length - 1] !== e.cmd)) {
        cmdHistory.push(e.cmd);
      }
      maybeTimestamp(e.ts * 1000);
      outBubble(e.cmd);
      renderEntry(e);
    }
    if (entries.length) scroll();
  } catch (_) {}
}

// ── Raw keystroke forwarding (while process runs) ────────────────────────────
let currentJob = null;

function enterRawMode(jobId) {
  currentJob = jobId;
  input.disabled = true;
  input.value = '';
  input.classList.add('raw-mode');
  input.placeholder = 'Process running — keystrokes forwarded (Ctrl+C to interrupt)';
  btn.disabled = true;
  document.addEventListener('keydown', rawKeyHandler, true);
}

function exitRawMode() {
  document.removeEventListener('keydown', rawKeyHandler, true);
  currentJob = null;
  input.classList.remove('raw-mode');
  input.disabled = false;
  input.placeholder = 'Message';
  btn.disabled = false;
  input.focus();
}

function rawKeyHandler(e) {
  // Sudo dialog is open — collect keystrokes into our own buffer and render dots.
  // No focus tricks needed: rawKeyHandler runs in capture phase at document level.
  if (_sudoOpen) {
    if (e.key === 'Enter') {
      e.preventDefault(); e.stopPropagation(); submitSudoPwd();
    } else if (e.key === 'Escape') {
      e.preventDefault(); e.stopPropagation(); cancelSudo();
    } else if (e.key === 'Backspace') {
      e.preventDefault(); e.stopPropagation();
      _sudoBuf = _sudoBuf.slice(0, -1); _sudoRender();
    } else if (e.ctrlKey && e.key === 'u') {
      e.preventDefault(); e.stopPropagation();
      _sudoBuf = ''; _sudoRender();
    } else if (e.ctrlKey && e.key === 'v') {
      e.preventDefault(); e.stopPropagation();
      navigator.clipboard.readText().then(t => { _sudoBuf += t; _sudoRender(); }).catch(() => {});
    } else if (e.key.length === 1 && !e.ctrlKey && !e.metaKey && !e.altKey) {
      e.preventDefault(); e.stopPropagation();
      _sudoBuf += e.key; _sudoRender();
    } else {
      e.preventDefault(); e.stopPropagation();
    }
    return;
  }
  // Let browser keep its own shortcuts (reload, new tab, etc.)
  if (e.metaKey) return;
  if (e.ctrlKey && 'rltwnRLTWN'.includes(e.key)) return;

  let text = null;

  if (e.ctrlKey && !e.altKey) {
    if (e.key === 'c') { text = '\x03'; }
    else if (e.key === 'd') { text = '\x04'; }
    else if (e.key === 'z') { text = '\x1A'; }
    else if (e.key === '\\') { text = '\x1C'; }
    else if (e.key.length === 1) {
      const code = e.key.toUpperCase().charCodeAt(0) - 64;
      if (code >= 1 && code <= 26) text = String.fromCharCode(code);
    }
  } else if (!e.ctrlKey && !e.altKey && !e.metaKey) {
    if (e.key === 'Enter')     text = '\r';
    else if (e.key === 'Escape')    text = '\x1b';
    else if (e.key === 'Backspace') text = '\x7f';
    else if (e.key === 'Delete')    text = '\x1b[3~';
    else if (e.key === 'Tab')       text = '\t';
    else if (e.key === 'ArrowUp')   text = '\x1b[A';
    else if (e.key === 'ArrowDown') text = '\x1b[B';
    else if (e.key === 'ArrowRight')text = '\x1b[C';
    else if (e.key === 'ArrowLeft') text = '\x1b[D';
    else if (e.key === 'Home')      text = '\x1b[H';
    else if (e.key === 'End')       text = '\x1b[F';
    else if (e.key === 'PageUp')    text = '\x1b[5~';
    else if (e.key === 'PageDown')  text = '\x1b[6~';
    else if (e.key.length === 1)    text = e.key;
  }

  if (text !== null) {
    e.preventDefault();
    e.stopPropagation();
    sendInput(text);
  }
}

async function sendInput(text) {
  if (!currentJob) return;
  try {
    await api(`/input/${currentJob}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text }),
    });
  } catch (_) {}
}

// ── Send command ─────────────────────────────────────────────────────────────
async function sendCmd() {
  if (currentJob) return;
  const cmd = input.value.trim();
  if (!cmd) return;

  // Intercept "clear": wipe the chat feed instead of running the shell's clear.
  if (/^clear\s*$/.test(cmd)) {
    input.value = '';
    if (cmdHistory.length === 0 || cmdHistory[cmdHistory.length - 1] !== cmd) {
      cmdHistory.push(cmd);      // keep ↑-arrow recall, like a real shell
    }
    histIdx = -1; histDraft = '';
    clearScreen();
    return;                      // don't echo a bubble or call /run
  }

  const isExit = /^(exit|logout)(\s+\d+)?\s*$/.test(cmd);

  maybeTimestamp(Date.now());
  outBubble(cmd);
  thinkingRow();

  const size = computeTermSize();

  let jobId = null;
  try {
    const r = await api('/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ command: cmd, cols: size.cols, rows: size.rows }),
    });
    const data = await r.json();
    if (data.error) throw new Error(data.error);
    jobId = data.job_id;
  } catch (err) {
    removeThinking();
    inBubble(true).textContent = 'Failed: ' + err.message;
    return;
  }

  enterRawMode(jobId);

  const es = new EventSource('/stream/' + jobId);
  let termObj = null, first = true;

  const exitNote = (parentAppend, code) => {
    if (code === 0 || code === null) return;
    const note = document.createElement('div');
    note.className = 'term-exit-note err';
    note.textContent = `exited ${code}`;
    parentAppend(note);
  };

  const finishTerm = (code, interactive) => {
    removeThinking();
    if (first) {
      // No output. Successful → say nothing; only surface a real failure.
      if (code !== 0 && code !== null) {
        inBubble(true).textContent = `Exited with code ${code}`;
      }
      return;
    }
    const term = termObj.term;
    // Run post-processing only after xterm has parsed every queued write, so the
    // snapshot reflects the command's true final state. The hide-cursor write is
    // both a guaranteed non-empty payload (so the callback fires) and tidies the
    // live terminal during the brief moment before we swap in the snapshot.
    term.write('\x1b[?25l', () => {
      try {
        // Interactive apps repaint in place → only their final screen is
        // meaningful. Normal commands → freeze the entire scrollback.
        const html = snapshotTerminal(term, interactive);
        if (html.trim()) {
          const el = document.createElement('div');
          el.className = 'bubble in term-static';
          el.innerHTML = html;
          termObj.wrap.replaceWith(el);
          exitNote(n => el.appendChild(n), code);
        } else {
          // No meaningful output (e.g. top after quit) → leave just the command.
          termObj.row.remove();
          if (code !== 0 && code !== null) inBubble(true).textContent = `Exited with code ${code}`;
        }
        try { term.dispose(); } catch (_) {}
      } catch (err) {
        // Fallback: never leave a live terminal (cursor + inner scrollbar) on
        // screen — collapse it to its content height instead.
        try { fitTermToContent(term); } catch (_) {}
        console.error('finishTerm:', err);
      }
      scroll();
    });
  };

  es.onmessage = e => {
    const msg = JSON.parse(e.data);

    if (msg.type === 'output') {
      // Thinking dots stay at bottom while output fills in above them
      if (first) { termObj = createTermBubble(size.cols, size.rows); first = false; }
      termObj.term.write(msg.data);
      scroll();

    } else if (msg.type === 'sudo_prompt') {
      showSudoDialog(jobId, msg.data || '[sudo] password:', !!msg.retry);

    } else if (msg.type === 'cwd') {
      cwdEl.textContent = msg.path;

    } else if (msg.type === 'exit') {
      hideSudoDialog();   // dismiss if still open (e.g. user cancelled sudo)
      es.close();
      finishTerm(msg.code, !!msg.interactive);
      exitRawMode();
      if (isExit) setTimeout(sessionEnded, 200);

    } else if (msg.type === 'error') {
      es.close();
      hideSudoDialog();
      removeThinking();
      inBubble(true).textContent = 'Error: ' + msg.data;
      exitRawMode();

    } else if (msg.type === 'done') {
      es.close();
      hideSudoDialog();
      finishTerm(null, false);
      exitRawMode();
    }
  };

  es.onerror = () => {
    es.close();
    removeThinking();
    if (first) inBubble(true).textContent = 'Connection lost.';
    exitRawMode();
  };
}

// ── Tab completion ────────────────────────────────────────────────────────────
function currentToken() {
  const m = input.value.match(/(\S*)$/);
  return m ? m[1] : '';
}

function applyCompletion(token, repl) {
  const v = input.value;
  input.value = v.slice(0, v.length - token.length) + repl;
  input.setSelectionRange(input.value.length, input.value.length);
}

function commonPrefix(arr) {
  if (!arr.length) return '';
  let p = arr[0];
  for (const s of arr) {
    let i = 0;
    while (i < p.length && i < s.length && p[i] === s[i]) i++;
    p = p.slice(0, i);
    if (!p) break;
  }
  return p;
}

function hideCompletions() {
  document.getElementById('compbox')?.classList.remove('show');
}

function showCompletions(matches) {
  let box = document.getElementById('compbox');
  if (!box) { box = document.createElement('div'); box.id = 'compbox'; document.body.appendChild(box); }
  box.innerHTML = '';
  for (const m of matches.slice(0, 400)) {
    const item = document.createElement('span');
    item.className = 'compitem';
    const trimmed = m.replace(/[ ]$/, '');
    const isDir   = trimmed.endsWith('/');
    const base    = (isDir ? trimmed.slice(0, -1) : trimmed).split('/').pop();
    item.textContent = base + (isDir ? '/' : '');
    item.onclick = () => { applyCompletion(currentToken(), m); hideCompletions(); input.focus(); };
    box.appendChild(item);
  }
  box.classList.add('show');
}

async function doComplete() {
  if (currentJob) return;
  let res;
  try {
    res = await api('/complete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ line: input.value }),
    }).then(r => r.json());
  } catch (_) { return; }

  hideCompletions();
  const matches = res.matches || [];
  const token   = res.token || '';
  if (matches.length === 0) return;
  if (matches.length === 1) {
    applyCompletion(token, matches[0]);
  } else {
    const common = commonPrefix(matches);   // longest shared replacement (no trailing space)
    if (common.length > token.length) applyCompletion(token, common);
    else showCompletions(matches);
  }
}

input.addEventListener('keydown', e => {
  if (currentJob) return;   // raw mode handles its own keys
  if (e.key === 'Tab') { e.preventDefault(); doComplete(); return; }
  hideCompletions();
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendCmd(); }
  else if (e.key === 'ArrowUp')   { e.preventDefault(); historyUp(); }
  else if (e.key === 'ArrowDown') { e.preventDefault(); historyDown(); }
});

// ── Settings ─────────────────────────────────────────────────────────────────
let preSaveFont = currentFontSize;

async function openSettings() {
  preSaveFont = currentFontSize;
  const s = await api('/settings').then(r => r.json()).catch(() => ({ max_history_mb: 10 }));
  document.getElementById('hist-mb').value    = s.max_history_mb ?? 10;
  document.getElementById('font-slider').value = currentFontSize;
  document.getElementById('font-display').textContent = currentFontSize;
  // Install/uninstall is always reachable here: show "Uninstall" when the
  // system service is active, otherwise offer "Set Up System Service…".
  hideUninstallConfirm();
  const sec = document.getElementById('setup-section');
  sec.style.display = '';
  let installed = false;
  try {
    const cfg = await fetch('/setup/status').then(r => r.json());
    installed = cfg.method === 'admin';
  } catch (_) {}
  document.getElementById('setup-mode-label').textContent = installed ? 'system (admin)' : 'user mode';
  document.getElementById('uninstall-btn').style.display = installed ? '' : 'none';
  document.getElementById('install-btn').style.display    = installed ? 'none' : '';
  document.getElementById('settings-overlay').classList.add('open');
}

function previewFont(n) {
  document.getElementById('font-display').textContent = n;
  applyFont(parseInt(n));
}

async function saveSettings() {
  const size = parseInt(document.getElementById('font-slider').value);
  const mb   = parseFloat(document.getElementById('hist-mb').value) || 10;
  currentFontSize = size;
  localStorage.setItem('termsite_font', size);
  applyFont(size);
  await api('/settings', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ max_history_mb: mb }),
  }).catch(() => {});
  document.getElementById('settings-overlay').classList.remove('open');
}

function closeSettings() {
  applyFont(preSaveFont);  // revert preview
  hideUninstallConfirm();
  document.getElementById('settings-overlay').classList.remove('open');
}

function showUninstallConfirm() {
  document.getElementById('uninstall-btn').style.display = 'none';
  document.getElementById('uninstall-confirm').style.display = 'block';
}

function hideUninstallConfirm() {
  const c = document.getElementById('uninstall-confirm');
  if (!c) return;
  c.style.display = 'none';
  // Restore the uninstall trigger button (only meaningful while installed; when
  // not installed openSettings() keeps it hidden and shows Install instead).
  document.getElementById('uninstall-btn').style.display = '';
}

function goInstall() {
  // Hand off to the full setup wizard (admin-auth flow + post-install handoff).
  window.location.href = '/setup';
}

async function runUninstall() {
  document.getElementById('uninstall-confirm-body').innerHTML =
    '<div style="text-align:center;padding:6px;font-size:13px;color:var(--text-light)">Uninstalling…</div>';
  try {
    const r = await fetch('/setup/uninstall', { method: 'POST' });
    const d = await r.json();
    if (d.ok) {
      closeSettings();
      showToast('System setup removed. Restart to apply.');
    } else {
      document.getElementById('uninstall-confirm-body').innerHTML =
        `<div style="color:#FF3B30;font-size:13px;margin-bottom:8px">${d.error || 'Uninstall failed.'}</div>` +
        (d.detail ? `<pre style="font-size:11px;white-space:pre-wrap;word-break:break-all;color:var(--text-light)">${d.detail}</pre>` : '') +
        `<button class="mbtn mbtn-sec" style="margin-top:10px;width:100%" onclick="hideUninstallConfirm()">Close</button>`;
    }
  } catch (e) {
    document.getElementById('uninstall-confirm-body').innerHTML =
      `<div style="color:#FF3B30;font-size:13px">Connection error: ${e.message}</div>` +
      `<button class="mbtn mbtn-sec" style="margin-top:10px;width:100%" onclick="hideUninstallConfirm()">Close</button>`;
  }
}

async function clearHistory() {
  if (!confirm('Delete all saved command history? This cannot be undone.')) return;
  await api('/clear-history', { method: 'POST' }).catch(() => {});
  cmdHistory.length = 0;
  histIdx = -1; histDraft = '';
  closeSettings();
  showToast('History file cleared');
}

// ── Init ─────────────────────────────────────────────────────────────────────
loadHistory().then(() => input.focus());

if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/sw.js', { scope: '/' }).catch(() => {});
}
</script>
</body>
</html>"""

# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/vendor/<path:fname>")
def vendor(fname):
    # Serve the bundled xterm.js assets (offline-capable packaged builds).
    return send_from_directory(VENDOR_DIR, fname, max_age=31536000)

# ── PWA assets ────────────────────────────────────────────────────────────────
@app.route("/manifest.json")
def pwa_manifest():
    return jsonify({
        "name": "ThisMachine",
        "short_name": "ThisMachine",
        "description": "iMessage-style shell in your browser",
        "start_url": "/",
        "display": "standalone",
        "background_color": "#000000",
        "theme_color": "#007AFF",
        "icons": [
            {"src": "/icon.svg", "sizes": "any", "type": "image/svg+xml", "purpose": "any maskable"},
        ],
    })

@app.route("/sw.js")
def service_worker():
    # Minimal pass-through service worker — required for PWA installability.
    js = "self.addEventListener('fetch',e=>e.respondWith(fetch(e.request)));"
    return Response(js, mimetype="application/javascript",
                    headers={"Service-Worker-Allowed": "/"})

@app.route("/icon.svg")
def icon_svg():
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">'
        '<defs>'
        '<linearGradient id="g" x1="0" y1="0" x2="0" y2="1">'
        '<stop offset="0%" stop-color="#007AFF"/>'
        '<stop offset="100%" stop-color="#5856D6"/>'
        '</linearGradient>'
        '</defs>'
        '<rect x="4" y="4" width="92" height="92" rx="22" ry="22" fill="url(#g)"/>'
        '<text x="50" y="67" font-family="SF Pro,Helvetica Neue,Arial,sans-serif"'
        ' font-size="44" font-weight="700" fill="white" text-anchor="middle"'
        ' letter-spacing="-1">TM</text>'
        '</svg>'
    )
    return Response(svg, mimetype="image/svg+xml",
                    headers={"Cache-Control": "max-age=86400"})

# Local vendored assets when present (self-contained AppImage); otherwise the
# CDN, so running from a bare source checkout still works.
if HAS_VENDOR:
    _XTERM_CSS = "/vendor/xterm.min.css"
    _XTERM_JS  = "/vendor/xterm.min.js"
else:
    _XTERM_CSS = "https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.min.css"
    _XTERM_JS  = "https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.min.js"

@app.route("/")
def index():
    page = (HTML.replace("__HOME__", HOME_DIR)
                .replace("__XTERM_CSS__", _XTERM_CSS)
                .replace("__XTERM_JS__", _XTERM_JS))
    # The HTML/JS is embedded in this process and changes whenever app.py is
    # edited. Tell the browser never to cache it, so a reload always loads the
    # current code instead of a stale page.
    return page, 200, {
        "Content-Type":  "text/html; charset=utf-8",
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma":        "no-cache",
        "Expires":       "0",
    }

@app.route("/history")
def get_history():
    return jsonify(load_history())

@app.route("/clear-history", methods=["POST"])
def clear_history():
    with hist_lock:
        try:
            os.unlink(HISTORY_FILE)
        except FileNotFoundError:
            pass
    return jsonify({"ok": True})

@app.route("/shutdown", methods=["POST"])
def shutdown():
    def _kill():
        time.sleep(0.25)
        os.kill(os.getpid(), signal.SIGTERM)
    threading.Thread(target=_kill, daemon=True).start()
    return jsonify({"ok": True})

@app.route("/settings", methods=["GET", "POST"])
def settings():
    if request.method == "GET":
        return jsonify(load_settings())
    data = request.get_json() or {}
    s = load_settings()
    if "max_history_mb" in data:
        s["max_history_mb"] = float(data["max_history_mb"])
    persist_settings(s)
    return jsonify(s)

@app.route("/run", methods=["POST"])
def run_command():
    data    = request.get_json(silent=True) or {}
    command = data.get("command", "").strip()
    if not command:
        return jsonify({"error": "empty command"}), 400

    cols = max(20, min(int(data.get("cols") or 80),  400))
    rows = max(4,  min(int(data.get("rows") or 24),  200))

    sid, session = get_session(request)
    job_id = str(uuid.uuid4())
    q: queue.Queue = queue.Queue()
    jobs[job_id] = q
    job_state[job_id] = {"session_id": sid}   # thread will add master + pid
    start_ts = time.time()

    threading.Thread(
        target=_run_command,
        args=(command, session, q, job_id, start_ts, (rows, cols)),
        kwargs={"sid": sid},
        daemon=True,
    ).start()
    return jsonify({"job_id": job_id})

def _completions(token: str, cwd: str, is_cmd: bool) -> list[str]:
    """Return full-token replacements for `token`.

    Command position (first word) completes against PATH executables + builtins.
    Otherwise completes filesystem paths relative to the session's cwd. Directory
    results end in '/', everything else in ' ' so the next word can follow."""
    slash = token.rfind("/")
    head  = token[:slash + 1] if slash >= 0 else ""
    frag  = token[slash + 1:] if slash >= 0 else token

    if is_cmd and slash < 0:
        seen: set[str] = set()
        results: list[str] = []
        for d in os.environ.get("PATH", "").split(os.pathsep):
            try:
                names = os.listdir(d)
            except OSError:
                continue
            for n in names:
                if n.startswith(frag) and n not in seen:
                    p = os.path.join(d, n)
                    if os.access(p, os.X_OK) and not os.path.isdir(p):
                        seen.add(n); results.append(n + " ")
        for b in BUILTINS:
            if b.startswith(frag) and b not in seen:
                seen.add(b); results.append(b + " ")
        return sorted(results)

    # Path completion
    base = os.path.expanduser(head) if head else ""
    if base and os.path.isabs(base):
        listing_dir = base
    elif base:
        listing_dir = os.path.join(cwd, base)
    else:
        listing_dir = cwd
    try:
        names = sorted(os.listdir(listing_dir))
    except OSError:
        return []
    show_hidden = frag.startswith(".")
    results = []
    for n in names:
        if not n.startswith(frag):
            continue
        if n.startswith(".") and not show_hidden:
            continue
        suffix = "/" if os.path.isdir(os.path.join(listing_dir, n)) else " "
        results.append(head + n + suffix)
    return results

@app.route("/complete", methods=["POST"])
def complete():
    _, session = get_session(request)
    cwd  = session.get("cwd", HOME_DIR)
    data = request.get_json(silent=True) or {}
    line = data.get("line", "")
    m      = re.search(r"(\S*)$", line)
    token  = m.group(1) if m else ""
    before = line[: len(line) - len(token)]
    is_cmd = (before.strip() == "" or
              before.rstrip().endswith(("|", "&&", "||", ";", "&", "(", "`")))
    return jsonify({"token": token, "matches": _completions(token, cwd, is_cmd)})

@app.route("/input/<job_id>", methods=["POST"])
def send_input(job_id):
    if not HAS_PTY:
        return jsonify({"error": "pty not available"}), 501
    state = job_state.get(job_id)
    if state is None:
        return jsonify({"error": "no such job"}), 404
    text = (request.get_json(silent=True, force=True) or {}).get("text", "")
    if text:
        # Ctrl+C: kill the process group directly — most reliable cross-shell method.
        if "\x03" in text:
            try:
                os.killpg(os.getpgid(state["pid"]), signal.SIGINT)
            except (ProcessLookupError, PermissionError, OSError):
                pass
        # Also write to the PTY so readline/ncurses apps see the keystroke.
        try:
            os.write(state["master"], text.encode())
        except OSError:
            pass
    return jsonify({"ok": True})

@app.route("/sudo-auth/<job_id>", methods=["POST"])
def sudo_auth(job_id):
    """Receive the sudo password from the client's native dialog, write it to
    the PTY, and cache it for 5 minutes so consecutive sudo commands don't ask."""
    if not HAS_PTY:
        return jsonify({"error": "pty not available"}), 501
    state = job_state.get(job_id)
    if state is None:
        return jsonify({"error": "no such job"}), 404
    data = request.get_json(silent=True, force=True) or {}
    pwd  = data.get("password", "")
    if pwd:
        # Cache encrypted for the session (5-minute window).
        # _enc_pwd uses an ephemeral Fernet key — never stored to disk.
        sid = state.get("session_id", "")
        if sid and sid in sessions:
            sessions[sid]["sudo_pwd"] = _enc_pwd(pwd)
            sessions[sid]["sudo_exp"] = time.time() + 300
        # Write password + Enter to the PTY.
        try:
            os.write(state["master"], (pwd + "\r").encode())
        except OSError:
            pass
    return jsonify({"ok": True})

@app.route("/stream/<job_id>")
def stream(job_id):
    q = jobs.get(job_id)
    if q is None:
        return "job not found", 404

    def generate():
        try:
            while True:
                item = q.get(timeout=600)
                if item is None:
                    yield f"data: {json.dumps({'type': 'done'})}\n\n"
                    break
                yield f"data: {json.dumps(item)}\n\n"
        finally:
            jobs.pop(job_id, None)

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )

# ── First-run setup wizard ────────────────────────────────────────────────────
_SETUP_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Set Up ThisMachine</title>
<style>
:root{color-scheme:light dark}
@media(prefers-color-scheme:dark){:root{
  --bg:#000;--card:#1C1C1E;--text:#fff;--text2:rgba(255,255,255,.55);
  --sep:rgba(255,255,255,.12);--blue:#0A84FF;--green:#30D158;--red:#FF453A;
}}
@media(prefers-color-scheme:light){:root{
  --bg:#F2F2F7;--card:#fff;--text:#000;--text2:rgba(0,0,0,.45);
  --sep:rgba(0,0,0,.10);--blue:#007AFF;--green:#34C759;--red:#FF3B30;
}}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
  min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
.page{max-width:500px;width:100%;display:flex;flex-direction:column;gap:20px}
.hd{display:flex;flex-direction:column;align-items:center;gap:10px;text-align:center}
.app-icon{width:64px;height:64px;border-radius:16px;
  background:linear-gradient(145deg,#007AFF,#5856D6);
  display:flex;align-items:center;justify-content:center}
h1{font-size:22px;font-weight:700;letter-spacing:-.3px}
.sub{font-size:14px;color:var(--text2);line-height:1.5;max-width:340px}
.card{background:var(--card);border-radius:16px;padding:18px 20px;
  border:2px solid transparent;transition:border-color .15s}
.card.rec{border-color:var(--blue)}
.card-hd{display:flex;align-items:center;gap:12px;margin-bottom:10px}
.c-icon{width:36px;height:36px;border-radius:10px;display:flex;align-items:center;
  justify-content:center;flex-shrink:0}
.c-icon.bl{background:rgba(0,122,255,.13);color:var(--blue)}
.c-icon.gr{background:rgba(128,128,128,.13);color:var(--text2)}
.c-title{font-size:15px;font-weight:600}
.badge{font-size:10px;font-weight:700;background:var(--blue);color:#fff;
  padding:2px 7px;border-radius:20px;margin-left:8px;letter-spacing:.4px}
.c-desc{font-size:13px;color:var(--text2);line-height:1.5}
.bullets{margin-top:10px;display:flex;flex-direction:column;gap:6px}
.bl-row{display:flex;align-items:flex-start;gap:8px;font-size:13px;color:var(--text2)}
.bl-row svg{flex-shrink:0;margin-top:1px}
.btn{width:100%;padding:13px;border-radius:12px;font-size:15px;font-weight:600;
  border:none;cursor:pointer;transition:opacity .15s}
.btn:hover{opacity:.85}.btn:disabled{opacity:.4;cursor:default}
.btn-pri{background:var(--blue);color:#fff}
.btn-sec{background:var(--card);color:var(--text)}
.skip-box{background:var(--card);border-radius:14px;padding:14px 16px;
  display:flex;flex-direction:column;gap:10px}
.never-row{display:flex;align-items:center;gap:8px;font-size:13px;color:var(--text2)}
.never-row input{accent-color:var(--blue);width:16px;height:16px;cursor:pointer}
/* Status panel */
#st{display:none;background:var(--card);border-radius:16px;padding:24px 20px;
  display:flex;flex-direction:column;align-items:center;gap:12px}
#st.show{display:flex}
.st-icon{width:48px;height:48px;border-radius:50%;display:flex;align-items:center;justify-content:center}
.st-icon.spin{background:rgba(0,122,255,.12)}
.st-icon.ok{background:rgba(48,209,88,.12)}
.st-icon.err{background:rgba(255,69,58,.12)}
@keyframes rot{to{transform:rotate(360deg)}}
.spin svg{animation:rot 1s linear infinite}
#st-title{font-size:16px;font-weight:600}
#st-msg{font-size:13px;color:var(--text2);text-align:center;line-height:1.5}
#st-detail{font-size:11px;font-family:monospace;background:rgba(128,128,128,.08);
  border-radius:8px;padding:10px;color:var(--text2);white-space:pre-wrap;
  word-break:break-all;max-height:110px;overflow-y:auto;width:100%;display:none}
#st-acts{display:none;flex-direction:column;gap:8px;width:100%}
</style>
</head>
<body>
<div class="page">
  <div class="hd">
    <div class="app-icon">
      <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
        <rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/>
        <path d="M6 8l3 3-3 3M13 14h4"/>
      </svg>
    </div>
    <h1>Set Up ThisMachine</h1>
    <p class="sub">Choose how you'd like to run ThisMachine. You can change this later in Settings.</p>
  </div>

  <div id="main">
    <div style="display:flex;flex-direction:column;gap:12px">
      <div class="card rec">
        <div class="card-hd">
          <div class="c-icon bl">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
          </div>
          <span class="c-title">System setup<span class="badge">RECOMMENDED</span></span>
        </div>
        <p class="c-desc">Installs a background service and registers a local domain. Requires your admin password once.</p>
        <div class="bullets">
          <div class="bl-row"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--green)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>Available at <strong style="margin-left:3px">https://thismachine.chat</strong></div>
          <div class="bl-row"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--green)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>Port 443 — no port number in the URL</div>
          <div class="bl-row"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--green)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>Starts automatically on login</div>
          <div class="bl-row"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--green)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>HTTP redirects automatically to HTTPS</div>
        </div>
      </div>

      <div class="card">
        <div class="card-hd">
          <div class="c-icon gr">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>
            </svg>
          </div>
          <span class="c-title">User mode</span>
        </div>
        <p class="c-desc">Run with your current permissions. No admin password needed.</p>
        <div class="bullets">
          <div class="bl-row"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--text2)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>Available at <strong style="margin-left:3px">https://thismachine.localhost:5000</strong></div>
          <div class="bl-row"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--text2)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>Must be launched manually each session</div>
        </div>
      </div>
    </div>

    <div style="display:flex;flex-direction:column;gap:10px;margin-top:16px">
      <button class="btn btn-pri" onclick="doSetup()">Set Up with Admin Access</button>
      <div class="skip-box">
        <div class="never-row">
          <input type="checkbox" id="never-cb">
          <label for="never-cb">Don't ask again — always run in user mode</label>
        </div>
        <button class="btn btn-sec" style="padding:10px" onclick="doSkip()">Continue in User Mode</button>
      </div>
    </div>
  </div>

  <div id="st">
    <div class="st-icon spin" id="st-icon">
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--blue)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M21 12a9 9 0 1 1-6.22-8.56"/>
      </svg>
    </div>
    <div id="st-title">Setting up…</div>
    <div id="st-msg">An administrator password prompt will appear momentarily.</div>
    <div id="st-detail"></div>
    <div id="st-acts"></div>
  </div>
</div>
<script>
function showStatus(icon, title, msg, detail, btns) {
  document.getElementById('main').style.display = 'none';
  const st = document.getElementById('st');
  st.className = 'show';
  const ic = document.getElementById('st-icon');
  ic.className = 'st-icon ' + icon;
  ic.innerHTML = icon === 'spin'
    ? '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--blue)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12a9 9 0 1 1-6.22-8.56"/></svg>'
    : icon === 'ok'
    ? '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--green)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>'
    : '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--red)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>';
  document.getElementById('st-title').textContent = title;
  document.getElementById('st-msg').innerHTML = msg;
  const dd = document.getElementById('st-detail');
  if (detail) { dd.textContent = detail; dd.style.display = 'block'; }
  else { dd.style.display = 'none'; }
  const acts = document.getElementById('st-acts');
  if (btns && btns.length) {
    acts.style.display = 'flex';
    acts.innerHTML = btns.map(b =>
      `<button class="btn ${b.pri ? 'btn-pri' : 'btn-sec'}" onclick="act('${b.id}')">${b.label}</button>`
    ).join('');
  } else { acts.style.display = 'none'; }
}
async function act(id) {
  if (id === 'home')  window.location.href = '/';
  if (id === 'retry') window.location.reload();
  if (id === 'skip')  await doSkip();
  if (id === 'open')  window.location.href = 'https://thismachine.chat';
}
async function doSetup() {
  showStatus('spin', 'Setting up…', 'An administrator password prompt will appear momentarily.', null, null);
  try {
    const r = await fetch('/setup/run', { method: 'POST' });
    const d = await r.json();
    if (d.ok) {
      const target = d.target || 'https://thismachine.chat';
      showStatus('spin', 'Handing off…',
        'Starting the system service at <strong>' + target + '</strong>…', null, null);
      const goNow = () => {
        // First visit shows the self-signed-cert warning — a top-level
        // navigation lets the user click through it (a background fetch can't).
        showStatus('spin', 'Opening…',
          'Redirecting to <strong>' + target + '</strong>. If your browser shows a ' +
          'certificate warning, choose <em>Advanced → Proceed</em> to continue.',
          null, [{ id:'open', label:'Open ' + target, pri:true }]);
        window.location.href = target;
      };
      if (d.keepalive) {
        // We stay alive on :5000; poll our own origin (no cert/mixed-content
        // problem) until the new service answers on :443, then hand off.
        let tries = 0;
        const poll = setInterval(async () => {
          tries++;
          let up = false;
          try { up = (await fetch('/setup/probe').then(x => x.json())).up; } catch (_) {}
          if (up) {
            clearInterval(poll);
            // Tell the leftover user-mode process to exit, then navigate.
            fetch('/setup/done', { method: 'POST' }).catch(() => {});
            goNow();
          } else if (tries >= 40) {           // ~60 s safety valve
            clearInterval(poll);
            showStatus('err', 'Service did not start',
              'The system service was installed but is not yet listening on ' +
              '<strong>' + target + '</strong>.', null,
              [{ id:'open', label:'Open ' + target, pri:true },
               { id:'retry', label:'Try Again', pri:false }]);
          }
        }, 1500);
      } else {
        // We had to free port 443 and are exiting; can't poll ourselves.
        // Give systemd a moment to claim the port, then navigate top-level.
        setTimeout(goNow, 3500);
      }
    } else {
      showStatus('err', 'Setup failed', d.error || 'Could not complete setup.', d.detail || null,
        [{ id:'retry', label:'Try Again', pri:true }, { id:'skip', label:'Continue in User Mode', pri:false }]
      );
    }
  } catch(e) {
    showStatus('err', 'Connection error', e.message, null,
      [{ id:'retry', label:'Try Again', pri:true }, { id:'skip', label:'Continue in User Mode', pri:false }]
    );
  }
}
async function doSkip() {
  const never = document.getElementById('never-cb')?.checked ?? false;
  await fetch('/setup/skip', { method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ never }) });
  window.location.href = '/';
}
</script>
</body>
</html>
"""

@app.route("/setup")
def setup_page():
    # Only the installed system service has nothing left to set up; otherwise
    # always serve the wizard (even after a prior "skip") so it can reappear on
    # launch and so the Settings → Install entry can reach it.
    cfg = _read_setup_cfg()
    if cfg.get("method") == "admin":
        return redirect("/")
    return Response(_SETUP_HTML, mimetype="text/html",
                    headers={"Cache-Control": "no-store"})

@app.route("/setup/run", methods=["POST"])
def setup_run():
    """Run the privileged setup script via pkexec (graphical auth dialog)."""
    svc = "\n".join([
        "[Unit]",
        "Description=ThisMachine Web Terminal",
        "After=network.target",
        "",
        "[Service]",
        "Type=simple",
        f"User={_RUN_USER}",
        f"ExecStart={_EXEC_PATH}",
        "Restart=on-failure",
        "RestartSec=3",
        # No rate-limit: lets systemd keep retrying every 3 s until the port
        # is free (i.e. until the currently-running process has exited).
        "StartLimitIntervalSec=0",
        "Environment=TERMSITE_OPEN_BROWSER=0",
        "AmbientCapabilities=CAP_NET_BIND_SERVICE",
        "CapabilityBoundingSet=CAP_NET_BIND_SERVICE",
        "",
        "[Install]",
        "WantedBy=multi-user.target",
        "",
    ])
    svc_b64 = base64.b64encode(svc.encode()).decode()
    script = f"""#!/bin/bash
set -euo pipefail
# 1. /etc/hosts entry
if ! grep -qF 'thismachine.chat' /etc/hosts; then
    printf '\\n# ThisMachine local domain\\n127.0.0.1 thismachine.chat\\n::1 thismachine.chat\\n' >> /etc/hosts
fi
# 2. systemd service
printf '%s' '{svc_b64}' | base64 -d > /etc/systemd/system/thismachine.service
chmod 644 /etc/systemd/system/thismachine.service
systemctl daemon-reload
systemctl enable thismachine
# 3. Start the service now. It will fail because the current server still holds
# the port, but with StartLimitIntervalSec=0 systemd keeps retrying every 3 s
# until the port is free after the handoff.
systemctl start thismachine || true
"""
    fd, script_path = tempfile.mkstemp(suffix=".sh", prefix="thismachine_setup_")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(script)
        os.chmod(script_path, 0o700)
        result = subprocess.run(
            ["pkexec", "bash", script_path],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode == 0:
            _write_setup_cfg(done=True, method="admin")
            # Delete cached TLS cert so it is regenerated on next start with the
            # correct BROWSER_HOST (thismachine.chat) as the CN.
            for p in (_CERT_FILE, _KEY_FILE):
                try: os.unlink(p)
                except OSError: pass
            # Handoff strategy depends on whether *this* process is sitting on the
            # port the new systemd service needs (443).
            #
            # Common case (user mode): we fell back to port 5000, so we do NOT
            # hold 443. Stay alive so the wizard page can keep polling us
            # same-origin (/setup/probe) to learn when the new service is up —
            # a same-origin request avoids the self-signed-cert / mixed-content
            # traps that make a cross-origin background fetch to the new HTTPS
            # endpoint impossible. The client tells us to exit via /setup/done
            # once it has navigated away.
            #
            # Edge case (we're already on 443): we must exit so systemd can bind
            # the port; the client falls back to a timed top-level navigation.
            keepalive = (PORT != 443)
            if not keepalive:
                def _handoff():
                    time.sleep(0.5)
                    os.kill(os.getpid(), signal.SIGINT)
                threading.Thread(target=_handoff, daemon=True).start()
            return jsonify({"ok": True, "keepalive": keepalive,
                            "target": "https://thismachine.chat"})
        err = (result.stderr or result.stdout or "").strip()
        return jsonify({"ok": False,
                        "error": "Administrator authentication failed or was cancelled.",
                        "detail": err or f"pkexec exited {result.returncode}"})
    except subprocess.TimeoutExpired:
        return jsonify({"ok": False, "error": "Setup timed out after 2 minutes.", "detail": ""})
    except FileNotFoundError:
        return jsonify({"ok": False,
                        "error": "pkexec not found — PolicyKit is required for graphical authentication.",
                        "detail": "Install policykit-1 (Debian/Ubuntu) or polkit (Fedora/Arch)."})
    finally:
        try: os.unlink(script_path)
        except OSError: pass

@app.route("/setup/skip", methods=["POST"])
def setup_skip():
    data = request.get_json(silent=True) or {}
    _write_setup_cfg(done=True, method="skip", never=bool(data.get("never")))
    return jsonify({"ok": True})

@app.route("/setup/status")
def setup_status():
    return jsonify(_read_setup_cfg())

@app.route("/setup/probe")
def setup_probe():
    """Same-origin liveness check for the new system service.

    Returns {"up": true} once something is accepting TCP connections on port
    443 (the systemd service's proxy socket). This is a raw TCP connect, so the
    new service's self-signed certificate is irrelevant — unlike a browser
    fetch(), which would reject on the untrusted-cert handshake. The wizard
    polls this from its (already-trusted, same-origin) page to know when it's
    safe to navigate to https://thismachine.chat."""
    import socket as _sk
    up = False
    try:
        with _sk.create_connection(("127.0.0.1", 443), timeout=0.5):
            up = True
    except OSError:
        up = False
    return jsonify({"up": up})

@app.route("/setup/done", methods=["POST"])
def setup_done():
    """Client signals it has navigated to the new service; exit so this leftover
    user-mode process doesn't linger. No-op-safe: the new systemd service owns
    the user-facing ports, so quitting here is clean."""
    def _quit():
        time.sleep(0.5)
        os.kill(os.getpid(), signal.SIGINT)
    threading.Thread(target=_quit, daemon=True).start()
    return jsonify({"ok": True})

@app.route("/setup/uninstall", methods=["POST"])
def setup_uninstall():
    """Reverse all admin-setup changes via a pkexec-authenticated shell script."""
    script = r"""#!/bin/bash
set -euo pipefail

# 1. Stop and disable the systemd service (ignore errors if not running/enabled)
systemctl stop    thismachine 2>/dev/null || true
systemctl disable thismachine 2>/dev/null || true

# 2. Delete the service file and reload systemd
rm -f /etc/systemd/system/thismachine.service
systemctl daemon-reload

# 3. Remove the thismachine.chat /etc/hosts entries and the comment line we added
sed -i '/thismachine\.chat/d'            /etc/hosts
sed -i '/^# ThisMachine local domain$/d' /etc/hosts
"""
    fd, script_path = tempfile.mkstemp(suffix=".sh", prefix="thismachine_uninstall_")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(script)
        os.chmod(script_path, 0o700)
        result = subprocess.run(
            ["pkexec", "bash", script_path],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode == 0:
            # Reset config so the setup wizard reappears on next AppImage launch.
            try: os.unlink(_SETUP_CFG)
            except OSError: pass
            return jsonify({"ok": True})
        err = (result.stderr or result.stdout or "").strip()
        return jsonify({"ok": False,
                        "error": "Uninstall failed — administrator authentication cancelled or denied.",
                        "detail": err or f"pkexec exited {result.returncode}"})
    except subprocess.TimeoutExpired:
        return jsonify({"ok": False, "error": "Uninstall timed out.", "detail": ""})
    except FileNotFoundError:
        return jsonify({"ok": False, "error": "pkexec not found.", "detail": ""})
    finally:
        try: os.unlink(script_path)
        except OSError: pass

# ── Entry point ───────────────────────────────────────────────────────────────
def _start_http_redirect() -> None:
    """Bind port 80 and 301-redirect every HTTP request to the HTTPS URL.

    Listens on both IPv4 and IPv6 loopback: the installer maps thismachine.chat
    to *both* 127.0.0.1 and ::1 in /etc/hosts, so a browser that resolves the
    name to ::1 must find the redirect there too. No-op if port 80 can't be
    bound (no cap_net_bind_service, or already in use)."""
    import socket as _sk
    _base = f"https://{BROWSER_HOST}" + ("" if PORT == 443 else f":{PORT}")

    def _handle(conn: "_sk.socket") -> None:
        try:
            buf = b""
            while b"\r\n" not in buf and len(buf) < 4096:
                chunk = conn.recv(512)
                if not chunk:
                    break
                buf += chunk
            path = "/"
            try:
                path = buf.decode(errors="replace").split()[1]
            except (IndexError, ValueError):
                pass
            conn.sendall((
                f"HTTP/1.1 301 Moved Permanently\r\n"
                f"Location: {_base}{path}\r\n"
                f"Content-Length: 0\r\n"
                f"Connection: close\r\n\r\n"
            ).encode())
        except OSError:
            pass
        finally:
            try: conn.close()
            except OSError: pass

    def _serve(srv: "_sk.socket") -> None:
        while True:
            try:
                conn, _addr = srv.accept()
                threading.Thread(target=_handle, args=(conn,), daemon=True).start()
            except OSError:
                break

    bound = False
    families = [(_sk.AF_INET, HOST)]
    if HOST in ("127.0.0.1", "localhost"):
        families.append((_sk.AF_INET6, "::1"))
    for fam, addr in families:
        try:
            srv = _sk.socket(fam, _sk.SOCK_STREAM)
            srv.setsockopt(_sk.SOL_SOCKET, _sk.SO_REUSEADDR, 1)
            if fam == _sk.AF_INET6:
                srv.setsockopt(_sk.IPPROTO_IPV6, _sk.IPV6_V6ONLY, 1)
            srv.bind((addr, 80))
            srv.listen(128)
            threading.Thread(target=_serve, args=(srv,), daemon=True).start()
            bound = True
        except OSError:
            pass
    if bound:
        print(f"  http:     redirect enabled (port 80 → {_base})")
    else:
        print(f"  http:     port 80 not bound (no privilege or in use); "
              f"HTTP→HTTPS still active on port {PORT}")


def _start_dual_mode(host: str, port: int, inner_port: int) -> bool:
    """Bind ``port`` and sniff every connection's first byte.

    TLS (0x16) → transparent byte-level tunnel to Flask on ``inner_port``.
    Plain HTTP  → read the request line, reply with 301 to HTTPS.

    Returns True if the proxy socket was bound successfully.
    """
    import socket as _sk
    _base = f"https://{BROWSER_HOST}" + ("" if port == 443 else f":{port}")

    def _pipe(src: "_sk.socket", dst: "_sk.socket") -> None:
        try:
            while True:
                data = src.recv(32768)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        finally:
            for s in (src, dst):
                try: s.shutdown(_sk.SHUT_RDWR)
                except OSError: pass
                try: s.close()
                except OSError: pass

    def _handle(conn: "_sk.socket", _addr) -> None:
        try:
            first = conn.recv(1, _sk.MSG_PEEK)
            if not first:
                return
            if first == b"\x16":        # TLS ClientHello — tunnel to Flask
                inner = _sk.create_connection(("127.0.0.1", inner_port))
                threading.Thread(target=_pipe, args=(conn, inner), daemon=True).start()
                threading.Thread(target=_pipe, args=(inner, conn), daemon=True).start()
            else:                       # Plain HTTP — redirect
                buf = b""
                while b"\r\n" not in buf and len(buf) < 4096:
                    chunk = conn.recv(512)
                    if not chunk:
                        break
                    buf += chunk
                path = "/"
                try:
                    path = buf.decode(errors="replace").split()[1]
                except (IndexError, ValueError):
                    pass
                conn.sendall((
                    f"HTTP/1.1 301 Moved Permanently\r\n"
                    f"Location: {_base}{path}\r\n"
                    f"Content-Length: 0\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode())
                conn.close()
        except OSError:
            pass

    def _accept(srv: "_sk.socket") -> None:
        while True:
            try:
                conn, addr = srv.accept()
                threading.Thread(target=_handle, args=(conn, addr), daemon=True).start()
            except OSError:
                break

    # Listen on IPv4 and (for loopback) IPv6 too, mirroring the dual A/AAAA
    # /etc/hosts entry the installer writes for thismachine.chat.
    families = [(_sk.AF_INET, host)]
    if host in ("127.0.0.1", "localhost"):
        families.append((_sk.AF_INET6, "::1"))
    bound = False
    for fam, addr in families:
        try:
            srv = _sk.socket(fam, _sk.SOCK_STREAM)
            srv.setsockopt(_sk.SOL_SOCKET, _sk.SO_REUSEADDR, 1)
            if fam == _sk.AF_INET6:
                srv.setsockopt(_sk.IPPROTO_IPV6, _sk.IPV6_V6ONLY, 1)
            srv.bind((addr, port))
            srv.listen(128)
            threading.Thread(target=_accept, args=(srv,), daemon=True).start()
            bound = True
        except OSError:
            pass
    return bound


def _run_server(ssl_ctx) -> None:
    """Start Flask, with HTTP→HTTPS detection on the main port when TLS is active."""
    if not ssl_ctx:
        app.run(host=HOST, port=PORT, threaded=True, debug=False)
        return

    try:
        from werkzeug.serving import make_server as _mk
    except ImportError:
        app.run(host=HOST, port=PORT, threaded=True, debug=False, ssl_context=ssl_ctx)
        return

    # Flask listens on a loopback port; the dual-mode proxy owns the user-facing port.
    inner_port = PORT + 10000
    try:
        inner = _mk("127.0.0.1", inner_port, app, ssl_context=ssl_ctx, threaded=True)
    except OSError:
        # inner_port already in use — fall back to Flask directly on PORT
        app.run(host=HOST, port=PORT, threaded=True, debug=False, ssl_context=ssl_ctx)
        return

    if _start_dual_mode(HOST, PORT, inner_port):
        inner.serve_forever()
    else:
        # Could not bind PORT for the proxy (e.g. already in use); clean up
        # the inner server and let Flask try directly.
        inner.server_close()
        app.run(host=HOST, port=PORT, threaded=True, debug=False, ssl_context=ssl_ctx)


def _open_browser_later(url: str = "") -> None:
    """Open the default browser once the server is accepting connections."""
    import socket, webbrowser
    _url = url or BROWSER_URL
    for _ in range(100):                      # up to ~10s
        try:
            with socket.create_connection((HOST, PORT), timeout=0.2):
                break
        except OSError:
            time.sleep(0.1)
    webbrowser.open(_url)

if __name__ == "__main__":
    import socket as _sock

    # Pre-test whether we can bind the configured port. Privileged ports
    # (<1024) require root or cap_net_bind_service; fall back to 5000 so the
    # app always starts rather than crashing with "Permission denied".
    _listen = PORT
    _fell_back = False
    if PORT < 1024:
        try:
            _s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
            _s.setsockopt(_sock.SOL_SOCKET, _sock.SO_REUSEADDR, 1)
            _s.bind((HOST, PORT))
            _s.close()
        except PermissionError:
            _listen = 5000
            _fell_back = True

    # Update globals so _open_browser_later() picks up the correct values.
    PORT = _listen
    BROWSER_URL = _make_browser_url(BROWSER_HOST, PORT)

    pty_status = "enabled" if HAS_PTY else "unavailable (no keystroke forwarding)"
    assets     = "vendored (offline)" if HAS_VENDOR else "CDN (needs internet)"
    if _TLS_CERT:
        mc = "thismachine.localhost.pem" in _TLS_CERT
        tls_status = "mkcert (trusted)" if mc else "self-signed (accept once in browser)"
    else:
        tls_status = "disabled (cryptography package missing)"
    print(f"\n  ThisMachine")
    print(f"  ─────────────────────────────────────────────")
    print(f"  {BROWSER_URL}")
    if _fell_back:
        _configured = int(os.environ.get("TERMSITE_PORT", "443"))
        print(f"  [notice] Port {_configured} needs elevated privileges → using {_listen}.")
        print(f"  Fix with (one-time, survives reboots):")
        print(f"    sudo setcap cap_net_bind_service=+ep $(readlink -f $(which python3))")
    print(f"  tls:      {tls_status}")
    print(f"  home:     {HOME_DIR}")
    print(f"  history:  {HISTORY_FILE}")
    print(f"  pty:      {pty_status}")
    print(f"  assets:   {assets}")
    if _TLS_NEW:
        print()
        print(f"  First launch: a self-signed cert was generated in {_CERT_DIR}")
        print(f"  Open the URL above, click Advanced → Proceed to accept it once.")
        print(f"  For a trusted cert (green padlock, no warning), run:")
        print(f"    mkcert -install")
        print(f"    mkcert -cert-file ~/.termsite_cert/thismachine.localhost.pem \\")
        print(f"           -key-file  ~/.termsite_cert/thismachine.localhost-key.pem \\")
        print(f"           thismachine.localhost 127.0.0.1")
    print(f"\n  Tip: install as PWA in Chrome for an app-like experience (no URL bar).")
    print(f"\n  Press Ctrl+C to stop\n")

    # HTTP → HTTPS redirect (no-op if port 80 can't be bound without privileges)
    _start_http_redirect()

    # AppImage/desktop launch: open browser, showing setup wizard on first run.
    if os.environ.get("TERMSITE_OPEN_BROWSER") == "1":
        _open_url = (BROWSER_URL + "/setup") if _should_show_setup() else BROWSER_URL
        threading.Thread(target=_open_browser_later, args=(_open_url,), daemon=True).start()

    ssl_ctx = (_TLS_CERT, _TLS_KEY) if _TLS_CERT else None
    _run_server(ssl_ctx)
