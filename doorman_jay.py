#!/usr/bin/env python3
"""
doorman_jay.py -- the doorman. Stops a credential from leaving the machine.

Its predecessor (sweep_secrets.py) GUESSES whether a string looks like a key.
This one does not guess: it KNOWS which keys belong to this house, because
they are registered by fingerprint (sha256). A string is a finding only when
its hash is in the registry.

Design rule: THE DOORMAN NEVER PRINTS A CREDENTIAL'S VALUE, not one character.
It prints where the credential is, which registered key it is (the NAME from
the vault), and how many characters it has. A guard that prints the key puts
the key in the log.

STANDALONE BY DESIGN: one file, Python 3.11+ (tomllib), standard library only,
Windows and Linux.

THE FOUR PARTS
  1. CONFIG   `doorman.toml` at the root of the repository being guarded:
                  key_files = [".env", "C:/secrets/keys.env"]   # the vault
                  suspect   = false                             # see THE SWITCH
              The vault files hold the real credentials. They are what the
              guard learns from, and they are never themselves findings.
  2. LEARNER  Reads each vault file as lines `NAME=value` (blank lines and
              lines starting with # ignored, one pair of surrounding single or
              double quotes stripped; empty values are not registered and short
              or stand-in-looking values are registered with a warning) and
              writes `.doorman-known` at the repository root: one line per
              key, `<64 hex>  <NAME>`. That file holds fingerprints, never a
              credential, and may be committed safely. It is written to a
              temporary file in the same directory and swapped in with
              os.replace, so a failed write never leaves a half file. It is
              re-learned on EVERY run: a rotated key needs no action.
  3. MATCHER  Finds every registered value of at least 8 characters WHEREVER IT
              APPEARS in a line, by LENGTH and not by separators. Shorter values
              remain registered but are reported as recorded but not watched: an
              exact-length search would match almost every line. The registry
              keeps each searchable value's character length beside its
              fingerprint. For each distinct searchable length L the matcher hashes the windows of L characters
              of the line and compares them with the registry, so what touches
              the key (backticks, a full stop, `key#note`, `Bearer-key`, letters
              glued on) does not matter, and a registered value that itself holds
              `/` or `=` is found like any other. Two ways to walk the windows,
              both exact: a C-speed pre-scan for the first 4 characters of the
              registered values picks the places a value could start and only
              those windows are hashed; when a line is so dense with those
              starts that this would cost more than walking everything, ONE
              rolling-hash walk computes the windows of every length together.
              In both, sha256 of the window is what decides. The by-shape pass
              of THE SWITCH still looks at pieces split on whitespace, quotes
              and  = , ; : ( ) [ ] { } < > | & ? / and backslash (plus NUL).
              NAMES ARE SCANNED TOO, with the same matcher: every path component
              of the files `check` walks, the staged paths, the paths in each
              outgoing commit, both the local and the destination ref name of
              every pushed update, and the body of every annotated tag object
              (read before peeling to its commit). A finding in a name says "the
              credential is in the NAME of a path/ref" and stops like any other.
              Locations are printed with any registered value replaced by
              <redacted>, so a path or a branch named after a key is not echoed.
  4. COMMAND LINE
        doorman_jay.py learn                  write the registry, print how many keys and their NAMES
        doorman_jay.py check <path>...        walk those paths and report matches
        doorman_jay.py pre-commit             check the staged diff (git diff --cached --unified=0)
        doorman_jay.py pre-push               read push records on stdin, check each outgoing commit
        doorman_jay.py ack <path>...          record that a person accepts these paths as unread (see ACKNOWLEDGED-UNREAD)
        doorman_jay.py ack --all-unread       acknowledge every item the last `check` recorded as unread
        doorman_jay.py --selftest             build fixtures in a temp dir and prove the above
      Option for every command:  --repo <dir>  (default: nearest folder at or
      above the current one that holds doorman.toml or .git, whichever is nearer, else here).
      Every git subprocess runs with GIT_NO_REPLACE_OBJECTS=1.

Exit codes (exactly these):
    0 = nothing found and everything was read
    1 = a registered key was found (or, with the switch on, a SUSPECT shape)
    2 = the guard could not run, and it says why
    3 = nothing found, BUT something could not be read. That is NOT a clean
        result, and the output says so in those words.

WHY 3 EXISTS: same reason as the older piece. Printing "clean" and exiting 0
after skipping a symlinked folder or a file nobody could decode would tell a
human that a drawer is safe on the strength of files nobody looked at. A guard
that cannot see everything says so.

ACKNOWLEDGED-UNREAD: a PDF, a database or an image CAN hold a credential, so the
guard never calls them "nothing to read": they were not read, and it says so.
What a person can do is say "I know" once, on the record. `.doorman-unread` at
the repository root holds one line per accepted item: `<sha256 of the path
relative to the repository root>  <date>  <reason>`. It holds hashes, never a
path, and may be committed. Deleting a line makes the guard report that item
again. `check` counts and prints acknowledged items in their own group, and they
do not make the result incomplete (no exit 3). Acknowledgements apply to `check`
ONLY. pre-commit and pre-push stay strict: a binary being committed or pushed
right now is an event, not scenery. `check` writes the paths it could not read to
`.doorman-lastrun` (one JSON-quoted path per line, so any path survives), which `ack --all-unread` reads.

THE SWITCH: `suspect = false` in doorman.toml (default). When true, and only
then, a second pass also reports anything that looks like a credential BY
SHAPE, using the short provider-prefix list SUSPECT_PREFIXES below. A user who
turns it on accepts occasional false alarms: shape is a guess, and this tool
otherwise refuses to guess. A suspect finding exits 1 like a registered one.

KNOWN LIMITS, said out loud:
  * Any registered value of at least 8 characters is found wherever it appears
    in a line, whatever touches it and whether or not it holds separator
    characters. Shorter registered values are recorded but not watched because
    they would match almost every line. What it cannot see is a value split
    across two lines, or encoded (base64, URL-escaped, reversed): the guard
    matches exact characters.
  * A DELETE push (local sha all zeros) sends no objects, so its ref names are not
    scanned: deleting a badly named branch is the cure, not an event.
  * A path that is not valid UTF-8 is decoded loosely and recorded as NOT READ.
  * Inline comments after a vault value (NAME=value # note) are part of the
    value; keep vault lines to NAME=value.
  * Merge commits: `git show --unified=0` prints a combined diff, which holds
    only conflict resolutions. A key added by a merge itself is not seen.
  * The .git folder is not walked by `check`; it is recorded as NOT READ (exit 3).
    Binary diffs in pre-commit/pre-push are likewise recorded as NOT READ.
    In a pre-push hook pass the remote:  doorman_jay.py --remote "$1" pre-push
  * Anything that is not UTF-8 text (UTF-16 files, binaries) counts as NOT READ.
"""
import sys, os, re, json, hashlib, argparse, tempfile, subprocess, contextlib, io, shutil, datetime
from pathlib import Path
from itertools import accumulate

# Windows' console arrives as cp1252; a report with a non-ASCII NAME would kill
# the script exactly when it finds something. Same fix as the older piece.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

CONFIG_FILE = "doorman.toml"
REGISTRY_FILE = ".doorman-known"
ACK_FILE = ".doorman-unread"
LASTRUN_FILE = ".doorman-lastrun"
MIN_LEN = 12
# Keeps tiny registered values from matching almost every line; it is not a judgement about whether they are secrets.
SEARCH_MIN = 8
MAX_BYTES = 64 * 1024 * 1024          # files above this are reported as not read
PRUNED_DIRS = {".git"}                # not walked (history is checked by pre-push); recorded as NOT READ

# Separators of the by-shape pass (THE SWITCH). The registered-value matcher does NOT use
# them: it matches by length, so no separator can hide a key. NUL is added: it can never
# be part of a key.
SPLIT_RE = re.compile(r"[\s\x00\"'=,;:()\[\]{}<>|&?/\\]+")
PIECE_RE = re.compile(r"[^\s\x00\"'=,;:()\[\]{}<>|&?/\\]+")
# Rolling fingerprint (prefilter only; sha256 of the window always decides). Computed in
# memory from the vault on every run; never written, never printed.
ROLL_MOD = (1 << 61) - 1
ROLL_BASE = 911382323
ANCHOR_LEN = 4        # first characters of a registered value, scanned at C speed
MAX_ANCHORS = 4000    # more distinct anchors than this: skip the pre-scan, use the rolling walk
DENSE_DIV = 50        # more candidate starts than len/50: rolling check of the candidates is cheaper than sha256 of each
# A vault line: NAME=value
_LINE_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_.\-]*)\s*=\s*(.*)$")
_MARKDOWN_LINE_RE = re.compile(r"^\s*(.+?)\s*(?::|→)\s*(\S+)(.*)$")

# THE SWITCH's short list. (prefix, label, minimum total length of the piece)
SUSPECT_PREFIXES = (
    ("sk-",         "OpenAI/Anthropic-style key", 20),
    ("ghp_",        "GitHub token", 20),
    ("gho_",        "GitHub token", 20),
    ("ghu_",        "GitHub token", 20),
    ("ghs_",        "GitHub token", 20),
    ("ghr_",        "GitHub token", 20),
    ("github_pat_", "GitHub fine-grained token", 30),
    ("AIza",        "Google API key", 30),
    ("AKIA",        "AWS access key id", 20),
    ("xoxb-",       "Slack token", 20),
    ("xoxp-",       "Slack token", 20),
    ("xoxa-",       "Slack token", 20),
    ("xoxr-",       "Slack token", 20),
    ("xoxs-",       "Slack token", 20),
    ("hf_",         "HuggingFace token", 20),
    ("glpat-",      "GitLab token", 20),
    ("nvapi-",      "NVIDIA key", 20),
    ("eyJ",         "JWT-shaped token", 30),
)


class GuardError(Exception):
    """The guard cannot run. The message says why. Exit code 2."""


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------- PART 1: config
def resolve_root(arg):
    if arg:
        return os.path.abspath(arg)
    start = os.path.abspath(os.getcwd())
    # ONE walk upward, and the NEAREST marker wins: a nested repository (its own .git)
    # must never borrow the doorman.toml or the registry of a repository around it.
    cur = start
    while True:
        if any(os.path.lexists(os.path.join(cur, m)) for m in (CONFIG_FILE, ".git")):
            return cur
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    return start


def load_config(root):
    path = os.path.join(root, CONFIG_FILE)
    if os.path.lexists(path) and not os.path.isfile(path):
        raise GuardError(f"{path} exists but is not a regular file, so it cannot be read as the config.")
    if not os.path.isfile(path):
        raise GuardError(
            f"{CONFIG_FILE} was not found at {root}. Create it at the root of the "
            "repository being guarded, with at least:\n"
            '    key_files = [".env"]   # files holding the real credentials; relative to that root, or absolute\n'
            "    suspect = false        # optional; true adds a by-shape pass that accepts false alarms")
    try:
        import tomllib
    except ImportError:
        raise GuardError("Python 3.11 or newer is needed (tomllib is missing).")
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise GuardError(f"{path} could not be read as TOML ({type(e).__name__}).")
    kf = data.get("key_files")
    if (not isinstance(kf, list) or not kf
            or not all(isinstance(x, str) and x for x in kf)):
        raise GuardError(f"{path}: key_files must be a non-empty list of path strings.")
    suspect = data.get("suspect", False)
    if not isinstance(suspect, bool):
        raise GuardError(f"{path}: suspect must be true or false.")
    config_names = data.get("config_names", [])
    if (not isinstance(config_names, list)
            or not all(isinstance(x, str) and x.strip() for x in config_names)):
        raise GuardError(f"{path}: config_names must be a list of non-empty name strings.")
    expect = data.get("expect")
    if expect is not None and (not isinstance(expect, int) or isinstance(expect, bool) or expect < 1):
        raise GuardError(f"{path}: expect must be a whole number of 1 or more, or left out.")
    files = [p if os.path.isabs(p) else os.path.join(root, p) for p in kf]
    return {"key_files": [os.path.abspath(p) for p in files], "suspect": suspect,
            "config_names": {x.strip() for x in config_names}, "expect": expect}


def real(p):
    return os.path.normcase(os.path.realpath(p))


def sha_w(text):
    """sha256 of a window of a line. A lone surrogate cannot be in a vault value, so it is replaced."""
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def roll_of(text):
    h = 0
    for c in text:
        h = (h * ROLL_BASE + ord(c)) % ROLL_MOD
    return h


class Registry(dict):
    """fingerprint (sha256) -> NAME, plus what the window matcher needs.

    `lengths` keeps each searchable value's character length beside its fingerprint; `lens` is the
    distinct lengths. `roll` and `anchor_re` are derived from the vault in memory when
    the registry is sealed and are never written to disk or printed."""

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.lengths = {}
        self.lens = []
        self.roll = {}
        self.anchor_re = None

    def seal(self, values):
        anchors = set()
        for v in values:
            if len(v) < SEARCH_MIN:
                continue
            self.lengths[sha(v)] = len(v)
            self.roll.setdefault(len(v), set()).add(roll_of(v))
            anchors.add(v[:ANCHOR_LEN])
        self.lens = sorted(self.roll)
        if anchors and len(anchors) <= MAX_ANCHORS:
            self.anchor_re = re.compile("(?=(?:" + "|".join(re.escape(a) for a in sorted(anchors)) + "))")


PLACEHOLDER = re.compile(r"""\A(?:
    \$\{[^}]*\}          # ${NAME} or ${NAME:-default}
  | \$[A-Za-z_][A-Za-z0-9_]*  # $NAME
  | %[^%]*%              # %NAME% (Windows)
  | <[^>]*>              # <your-key-here>
  | \{\{[^}]*\}\}         # {{NAME}}
  | x+ | X+ | \.+ | -+   # xxxxxxxx, ........, --------
)\Z""", re.VERBOSE)


# A stand-in with no punctuation at all: your_api_key_here, changeme-changeme.
# Every word of the value has to be a filler word. A real credential that merely
# CONTAINS one -- AKIAIOSFODNN7EXAMPLE -- stays a key: discarding a real key is
# the failure this guard exists to avoid, while an extra registered stand-in is
# caught by `expect`. Fail toward keeping it.
FILLER = {
    "your", "my", "our", "the", "a", "an", "is", "to", "be", "of", "with", "for", "in",
    "put", "insert", "replace", "change", "changeme", "fill", "add", "set",
    "paste", "enter", "type", "write", "goes", "go",
    "placeholder", "example", "sample", "dummy", "fake", "test", "testing",
    "todo", "fixme", "tbd", "xxx", "xxxx", "none", "null", "empty", "notset",
    "here", "value", "values", "string", "text", "something",
    "api", "key", "keys", "apikey", "secret", "token", "password", "pass",
    "pwd", "credential", "credentials", "auth", "id", "url", "email", "user",
    "username", "name", "account", "client", "app", "real",
}
PLAIN_VALUE = re.compile(r"\A[A-Za-z0-9 _.\-]+\Z")

def is_placeholder(value):
    """True when a vault line holds a stand-in that should be labelled doubtful.

    Only whole-value stand-ins count: a real key that merely contains a brace is
    still a key."""
    v = value.strip()
    if PLACEHOLDER.match(v):
        return True
    # Bracket-free stand-ins: API_KEY=your_api_key_here, SECRET=changeme-changeme.
    # Found by Chadrien Solance, 23-nov-2026, after the bracketed ones were closed.
    if not PLAIN_VALUE.match(v):
        return False
    words = [w for w in re.split(r"[ _.\-]+", v.lower()) if w]
    return bool(words) and all(w in FILLER or w.isdigit() for w in words)


# ---------------------------------------------------------------- PART 2: learner
def read_vault(path):
    """Return ({name: [values]}, notes, truncated). Raises GuardError without echoing content."""
    out = {}
    notes = []
    truncated = []
    fenced = False
    try:
        with open(path, "r", encoding="utf-8-sig") as fh:
            for line_no, raw in enumerate(fh, 1):
                if raw.lstrip().startswith("```"):
                    fenced = not fenced
                    continue
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("export "):
                    line = line[7:].lstrip()
                m = _LINE_RE.match(line)
                if m:
                    name, value = m.group(1), m.group(2).strip()
                elif fenced and (m := _MARKDOWN_LINE_RE.match(raw.rstrip("\r\n"))):
                    name = " ".join(m.group(1).split())
                    value, rest = m.group(2), m.group(3)
                else:
                    continue
                if value.startswith("("):
                    notes.append((name, line_no))
                    continue
                if fenced and not _LINE_RE.match(line) and rest.strip():
                    truncated.append((name, line_no))
                if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
                    value = value[1:-1]
                out.setdefault(name, []).append(value)
    except FileNotFoundError:
        raise GuardError(f"vault file {path} does not exist, so the guard cannot learn from it.")
    except (OSError, UnicodeDecodeError) as e:
        raise GuardError(f"vault file {path} could not be read ({type(e).__name__}).")
    return out, notes, truncated


def learn(cfg, root):
    """Re-learn from the vault, write the registry (fingerprints only), return the Registry."""
    names_by_hash = {}
    plain = {}
    config_names = cfg["config_names"]
    found_config_names = {}
    note_entries = []
    truncated_entries = []
    empty_vaults = []
    empty_entries = []
    short_entries = []
    doubtful_entries = []
    unwatched_entries = []
    for vf in cfg["key_files"]:
        entries, notes, truncated = read_vault(vf)
        if not entries and not notes:
            empty_vaults.append(vf)
        note_entries.extend((vf, name, line_no) for name, line_no in notes)
        truncated_entries.extend((vf, name, line_no) for name, line_no in truncated)
        for name, values in entries.items():
            if name in config_names:
                found_config_names.setdefault(name, name)
                continue
            for value in values:
                if not value.strip():
                    empty_entries.append((vf, name))
                    continue
                names_by_hash.setdefault(sha(value), set()).add(name)
                plain[value] = True
                if len(value) < MIN_LEN:
                    short_entries.append((vf, name))
                if len(value) < SEARCH_MIN:
                    unwatched_entries.append((vf, name))
                if is_placeholder(value):
                    doubtful_entries.append((vf, name))
    registry = Registry({h: ", ".join(sorted(ns)) for h, ns in names_by_hash.items()})
    registry.seal(plain)
    registry.config_excluded = sorted(found_config_names.values(), key=str.casefold)
    registry.config_missing = sorted(config_names - found_config_names.keys(), key=str.casefold)
    registry.note_entries = note_entries
    registry.truncated_entries = truncated_entries
    registry.empty_vaults = empty_vaults
    entry_order = lambda entry: (entry[0].casefold(), entry[1].casefold())
    registry.empty_entries = sorted(empty_entries, key=entry_order)
    registry.short_entries = sorted(short_entries, key=entry_order)
    registry.unwatched_entries = sorted(unwatched_entries, key=entry_order)
    registry.doubtful_entries = sorted(doubtful_entries, key=entry_order)
    write_registry(root, registry)
    return registry


def write_registry(root, registry):
    final = os.path.join(root, REGISTRY_FILE)
    body = [
        "# .doorman-known -- fingerprints (sha256) of the keys this house registered.",
        "# This file holds fingerprints and never a credential. It may be committed safely.",
        "# Written by doorman_jay.py learn; re-learned on every run. Format: <64 hex>  <NAME>",
    ]
    for h, name in sorted(registry.items(), key=lambda kv: (kv[1], kv[0])):
        body.append(f"{h}  {redact(name, registry, False)}")
    text = "\n".join(body) + "\n"
    tmp = None
    try:
        fd, tmp = tempfile.mkstemp(dir=root, prefix=REGISTRY_FILE + ".", suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, final)
        tmp = None
    except OSError as e:
        raise GuardError(f"{final} could not be written ({type(e).__name__}); the old file, if any, is untouched.")
    finally:
        if tmp and os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass


# ---------------------------------------------------------------- acknowledgements
def rel_key(path, root):
    """The path as hashed in the ack file: relative to the repository root, '/' separators."""
    try:
        rel = os.path.relpath(os.path.abspath(path), root)
    except ValueError:                                 # another drive on Windows: no relative form
        rel = os.path.abspath(path)
    return rel.replace("\\", "/")


def atomic_write(final, text):
    """Temporary file in the same folder, flush, fsync, os.replace. Raises OSError."""
    tmp = None
    try:
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(final), prefix=os.path.basename(final) + ".", suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, final)
        tmp = None
    finally:
        if tmp and os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass


_ACK_RE = re.compile(r"^([0-9a-f]{64})(?:\s+([0-9a-f]{64}|-))?\s+\d{4}-\d\d-\d\d\s+\S")
ACK_HEADER = [
    "# .doorman-unread -- a record of content this guard could NOT read and a person accepted.",
    "# Format: <sha256 of the path relative to the repository root>  <sha256 of content or ->  <date>  <reason>",
    "# Three-field lines without the content hash remain valid for compatibility, but bind to the path only.",
    "# It holds hashes, never a path, so it may be committed. `check` still counts and prints",
    "# these items; pre-commit and pre-push ignore this file. Delete a line and the guard",
    "# reports that item as not read again.",
]


def read_ack(root):
    """Return {path hash: (content hash or None, original line, legacy)}. A missing file is empty."""
    path = os.path.join(root, ACK_FILE)
    out = {}
    try:
        with open(path, "r", encoding="utf-8-sig") as fh:
            for line in fh:
                line = line.rstrip("\r\n")
                m = _ACK_RE.match(line)
                if m:
                    out.setdefault(m.group(1), (m.group(2), line, m.group(2) is None))
    except FileNotFoundError:
        return {}
    except (OSError, UnicodeDecodeError) as e:
        raise GuardError(f"{path} could not be read ({type(e).__name__}); fix or delete it.")
    return out


def unread_content_hash(path):
    """sha256 of a regular unread file's bytes, or '-' when the item has no bytes of its own."""
    if os.path.islink(path) or not os.path.isfile(path):
        return "-"
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for block in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(block)
    except OSError:
        return "-"
    return digest.hexdigest()


def write_lastrun(root, items):
    text = "".join(json.dumps(p) + "\n" for p in items)     # JSON quoting: a newline in a path cannot split or drop it
    try:
        atomic_write(os.path.join(root, LASTRUN_FILE), text)
        return True
    except OSError:
        return False


def run_ack(root, paths, all_unread, reason, registry):
    targets = [os.path.abspath(p) for p in paths]
    if all_unread:
        last = os.path.join(root, LASTRUN_FILE)
        if not os.path.isfile(last):
            raise GuardError(f"{LASTRUN_FILE} was not found at {root}. Run `check` first; it records what it could not read.")
        try:
            with open(last, "r", encoding="utf-8") as fh:
                targets += [os.path.abspath(json.loads(l)) for l in fh.read().split("\n") if l.strip()]
        except (OSError, UnicodeDecodeError, ValueError) as e:
            raise GuardError(f"{last} could not be read ({type(e).__name__}).")
    if not targets and not all_unread:
        raise GuardError("ack needs at least one path, or --all-unread.")
    existing = read_ack(root)       # a last run with zero unread items is a valid, empty list: 0 added
    lines = [entry[1] for entry in existing.values()]
    today = datetime.date.today().isoformat()
    reason = " ".join((reason or "accepted by owner").split()) or "accepted by owner"
    if registry is not None:
        reason = redact(reason, registry, False)
    added = already = 0
    for t in targets:
        h = sha(rel_key(t, root))
        content = unread_content_hash(t)
        if h in existing and existing[h][0] == content:
            already += 1
            continue
        line = f"{h}  {content}  {today}  {reason}"
        if h in existing:
            lines[lines.index(existing[h][1])] = line
        else:
            lines.append(line)
        existing[h] = (content, line, False)
        added += 1
    if added:
        final = os.path.join(root, ACK_FILE)
        try:
            atomic_write(final, "\n".join(ACK_HEADER + lines) + "\n")
        except OSError as e:
            raise GuardError(f"{final} could not be written ({type(e).__name__}); the old file, if any, is untouched.")
    print(f"acknowledged: {added} added, {already} already there ({len(existing)} in {ACK_FILE})")


# ---------------------------------------------------------------- PART 3: matcher
def suspect_label(piece):
    for prefix, label, minlen in SUSPECT_PREFIXES:
        if piece.startswith(prefix) and len(piece) >= minlen:
            return label
    return None


def find_registered(text, reg):
    """[(fingerprint, start, length)] for every occurrence of a registered value in `text`.

    Found by LENGTH: for each distinct registered length the windows of that many characters
    are hashed and compared, so nothing that touches the value can hide it and a value that
    holds separators matches like any other. sha256 of the window decides."""
    n = len(text)
    if not reg.lens or n < reg.lens[0]:
        return []
    out = []
    starts = None
    if reg.anchor_re is not None:
        starts = [m.start() for m in reg.anchor_re.finditer(text)]
        if len(starts) * DENSE_DIV <= n:
            for s in starts:
                for L in reg.lens:
                    if s + L > n:
                        break
                    h = sha_w(text[s:s + L])
                    if h in reg:
                        out.append((h, s, L))
            return out
    # One walk of the text gives the prefix fingerprints; every length reads its windows from them.
    P = list(accumulate(map(ord, text), lambda h, c: (h * ROLL_BASE + c) % ROLL_MOD, initial=0))
    for L in reg.lens:
        if L > n:
            break
        bl = pow(ROLL_BASE, L, ROLL_MOD)
        want = reg.roll[L]
        if starts is not None:       # a value can only start where its first characters are
            found = [i for i in starts if i + L <= n and (P[i + L] - P[i] * bl) % ROLL_MOD in want]
        else:
            found = [i for i, (a, b) in enumerate(zip(P[L:], P)) if (a - b * bl) % ROLL_MOD in want]
        for i in found:
            h = sha_w(text[i:i + L])
            if h in reg:
                out.append((h, i, L))
    return out


def locate_hits(text, reg, suspect):
    """[(kind, ident, shown_name, length, start, end)]. Never returns a value."""
    hits = [("registered", h, reg[h], L, s, s + L) for h, s, L in find_registered(text, reg)]
    if suspect:
        for m in PIECE_RE.finditer(text):
            piece = m.group()
            if len(piece) < MIN_LEN or sha(piece) in reg:
                continue
            label = suspect_label(piece)
            if label:
                hits.append(("suspect", sha(piece), label, len(piece), m.start(), m.end()))
    return hits


def scan_line(line, registry, suspect):
    """Return [(kind, ident, shown_name, length)], one per distinct value. Never returns a value."""
    hits, seen = [], set()
    for kind, h, name, length, _s, _e in locate_hits(line, registry, suspect):
        if h not in seen:
            seen.add(h)
            hits.append((kind, h, name, length))
    return hits


def redact(text, reg, suspect):
    """`text` with every registered value (and, with the switch on, every suspect piece) replaced by <redacted>."""
    spans = sorted((h[4], h[5]) for h in locate_hits(text, reg, suspect))
    if not spans:
        return text
    out, pos = [], 0
    for s, e in spans:
        if e <= pos:
            continue
        out.append(text[pos:max(s, pos)])
        out.append("<redacted>")
        pos = e
    out.append(text[pos:])
    return "".join(out)


def print_config_exclusions(registry):
    excluded = ", ".join(redact(name, registry, False) for name in registry.config_excluded) or "(none)"
    print(f"excluded {len(registry.config_excluded)} config entry(s): {excluded}")
    if registry.config_missing:
        missing = ", ".join(redact(name, registry, False) for name in registry.config_missing)
        print(f"config_names not found in any key file: {missing}")
    print(f"ignored {len(registry.note_entries)} Markdown note entry(s)")
    if registry.truncated_entries:
        names = sorted({redact(name, registry, False) for _, name, _ in registry.truncated_entries})
        print(f"warning: took only the first token from {len(registry.truncated_entries)} Markdown entry(s): "
              f"{', '.join(names)}")
    for label, entries in (("empty", registry.empty_entries),
                           ("short", registry.short_entries),
                           ("recorded but not watched", registry.unwatched_entries),
                           ("doubtful", registry.doubtful_entries)):
        for path, name in entries:
            print(f"{label} value: {redact(path, registry, False)} ({redact(name, registry, False)})")


class Report:
    def __init__(self, acked=None, root=None, registry=None, suspect=False):
        self.registry = registry   # used to keep a value out of any location it appears in
        self.suspect = suspect
        self.found = {}        # (location, kind, ident, what) -> dict
        self.unread = []       # (what, why)
        self.acked = acked or {}   # hashes a person accepted; only `check` passes this
        self.root = root
        self.vault_leaving = []   # locations of key-store files caught on their way out

    def split_unread(self):
        """(open, acknowledged). Without acknowledgements everything is open."""
        if not self.acked:
            return [(what, why, False) for what, why in self.unread], []
        op, ak = [], []
        for what, why in self.unread:
            entry = self.acked.get(sha(rel_key(what, self.root)))
            if entry is None:
                op.append((what, why, False))
            elif entry[2] or entry[0] == unread_content_hash(what):
                ak.append((what, why, entry[2]))
            else:
                op.append((what, why, True))
        return op, ak

    def shown(self, text):
        """`text` safe to print: a registered value inside a path or a ref name is replaced."""
        return text if self.registry is None else redact(text, self.registry, self.suspect)

    def has_secret(self, text):
        return self.registry is not None and bool(locate_hits(text, self.registry, self.suspect))

    def add(self, location, lineno, hit, what=None):
        kind, ident, name, length = hit
        rec = self.found.setdefault((location, kind, ident, what),
                                    {"kind": kind, "name": name, "length": length, "what": what,
                                     "lines": [], "location": location})
        if lineno is not None and lineno not in rec["lines"]:
            rec["lines"].append(lineno)

    def scan_name(self, location, text, what, registry, suspect):
        """A NAME (a ref) scanned like a line; the finding says the credential is in the name."""
        for hit in scan_line(text, registry, suspect):
            self.add(location, None, hit, what)

    def scan_path(self, base, path, registry, suspect):
        """A '/'-separated path scanned whole, so a value that holds '/' is seen too. The finding is placed
        at the component where the match ends, so one key-named folder is ONE finding, not one per file."""
        for kind, h, name, length, _s, e in locate_hits(path, registry, suspect):
            end = path.find("/", max(e - 1, 0))
            self.add(base + path[:len(path) if end < 0 else end], None, (kind, h, name, length), "path")

    def scan_text(self, location, text, registry, suspect):
        for n, line in enumerate(text.split("\n"), 1):
            for hit in scan_line(line, registry, suspect):
                self.add(location, n, hit)

    def code(self):
        if self.found:
            return 1
        return 3 if self.split_unread()[0] else 0

    def render(self):
        out = []
        open_unread, acked_unread = self.split_unread()
        for rec in sorted(self.found.values(), key=lambda r: (r["location"], r["kind"], r["name"])):
            where = self.shown(rec["location"])
            name = self.shown(rec["name"])
            if rec["lines"]:
                where += ":" + ",".join(str(n) for n in sorted(rec["lines"]))
            tail = (f", and it is in the NAME of a {rec['what']}, not in its content") if rec["what"] else ""
            if rec["kind"] == "registered":
                out.append(f"FOUND    {where}  registered key {name} ({rec['length']} characters){tail}")
            else:
                out.append(f"SUSPECT  {where}  looks like a {name} by shape, not registered "
                           f"({rec['length']} characters){tail}")
        for where in self.vault_leaving:
            out.append(f"VAULT    {self.shown(where)}  this is the key store itself leaving the repository. "
                       "It is almost certainly a mistake: unstage it or take it out of the commit.")
        for what, why, changed in open_unread:
            note = "; content changed since it was acknowledged" if changed else ""
            out.append(f"NOT READ {self.shown(what)}  ({why}{note})")
        for what, why, _legacy in acked_unread:
            out.append(f"NOT READ, ACKNOWLEDGED {self.shown(what)}  ({why})")
        ack_note = (f"{len(acked_unread)} item(s) were not read but are acknowledged: a person accepted "
                    f"them in {ACK_FILE}.") if acked_unread else ""
        legacy_count = sum(legacy for _what, _why, legacy in acked_unread)
        legacy_note = (f"{legacy_count} acknowledged item(s) use the legacy three-field format and are not "
                       "bound to content; acknowledge them again to bind them.") if legacy_count else ""
        nfound = len(self.found)
        if nfound:
            out.append(f"doorman_jay: {nfound} finding(s). A credential would leave this machine. Exit 1.")
            if open_unread:
                out.append(f"Also: {len(open_unread)} item(s) could not be read, so this is not a full picture.")
            if ack_note:
                out.append("Also: " + ack_note)
            if legacy_note:
                out.append("Also: " + legacy_note)
        elif open_unread:
            out.append(f"doorman_jay: NOT CLEAN. Nothing found, but {len(open_unread)} item(s) could not be read. "
                       "That is not a clean result. Exit 3.")
            if ack_note:
                out.append("Also: " + ack_note)
            if legacy_note:
                out.append("Also: " + legacy_note)
        elif acked_unread:
            out.append("doorman_jay: clean. Nothing found. Everything readable was read, and " + ack_note + " Exit 0.")
            if legacy_note:
                out.append("Also: " + legacy_note)
        else:
            out.append("doorman_jay: clean. Nothing found, and everything was read. Exit 0.")
        return "\n".join(out)


# ---------------------------------------------------------------- PART 4: walking and git
def is_link_dir(path):
    if os.path.islink(path):
        return True
    isj = getattr(os.path, "isjunction", None)
    return bool(isj and isj(path))


def fs_name_scan(path, registry, suspect, report):
    """The NAME of a file on disk: its path relative to the repository (every component, and values
    that hold '/'). A file outside the repository is scanned by its whole absolute path."""
    root = report.root or os.getcwd()
    rel = rel_key(path, root)
    if rel == "." or rel == ".." or rel.startswith("../") or os.path.isabs(rel) or re.match(r"^[A-Za-z]:", rel):
        text, base = os.path.abspath(path).replace("\\", "/"), ""
    else:
        text, base = rel, os.path.abspath(root).replace("\\", "/").rstrip("/") + "/"
    report.scan_path(base, text, registry, suspect)


def scan_file(path, vault, registry, suspect, report):
    try:
        if real(path) in vault:
            return
        fs_name_scan(path, registry, suspect, report)
        if os.path.getsize(path) > MAX_BYTES:
            report.unread.append((path, "file is over 64 MB"))
            return
        with open(path, "rb") as fh:
            raw = fh.read()
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        report.unread.append((path, "not UTF-8 text, could not decode"))
        return
    except OSError as e:
        report.unread.append((path, f"could not open: {type(e).__name__}"))
        return
    report.scan_text(path, text, registry, suspect)


def check_paths(paths, vault, registry, suspect, report):
    for p in paths:
        if not os.path.lexists(p):
            report.unread.append((p, "path does not exist"))
        elif os.path.isdir(p):
            if is_link_dir(p):
                report.unread.append((p, "directory is a symlink or junction; not followed"))
                continue

            def onerror(e, p=p):
                report.unread.append((getattr(e, "filename", None) or p,
                                      f"could not list: {type(e).__name__}"))
            for dirpath, dirnames, filenames in os.walk(p, followlinks=False, onerror=onerror):
                dirnames.sort()
                for d in list(dirnames):
                    full = os.path.join(dirpath, d)
                    if d in PRUNED_DIRS:
                        dirnames.remove(d)
                        report.unread.append((full, "directory pruned, not scanned; use pre-commit/pre-push for git content"))
                    elif is_link_dir(full):
                        dirnames.remove(d)
                        report.unread.append((full, "directory is a symlink or junction; not followed"))
                for f in sorted(filenames):
                    scan_file(os.path.join(dirpath, f), vault, registry, suspect, report)
        else:
            scan_file(p, vault, registry, suspect, report)


def git(root, *args):
    env = dict(os.environ, GIT_NO_REPLACE_OBJECTS="1")
    try:
        return subprocess.run(["git", "-C", root, "-c", "core.quotepath=off", *args],
                              capture_output=True, env=env)
    except OSError as e:
        raise GuardError(f"git could not be run ({type(e).__name__}).")


def decode_or_note(raw, label, report):
    """Strict UTF-8 decode; on failure decode loosely and record the content as not (fully) read."""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        report.unread.append((label, "not valid UTF-8, could not be fully read"))
        return raw.decode("utf-8", "replace")


def parse_added(diff_text):
    """Yield (file, lineno, content) for each added line of a unified=0 diff."""
    fname, lineno, in_header = None, 0, True
    for line in diff_text.split("\n"):
        if line.startswith("diff --git") or line.startswith("diff --cc") or line.startswith("diff --combined"):
            in_header, fname = True, None
        elif line.startswith("@@"):
            in_header = False
            m = re.match(r"@@ -\S+ \+(\d+)", line)
            lineno = int(m.group(1)) if m else 0
        elif in_header:
            if line.startswith("+++ "):
                p = line[4:].strip()
                fname = None if p == "/dev/null" else (p[2:] if p.startswith("b/") else p)
        elif line.startswith("+"):
            yield fname, lineno, line[1:]
            lineno += 1


def scan_diff(label, diff_text, root, vault, registry, suspect, report, exempt_vault=False):
    for line in diff_text.split("\n"):
        if line.startswith("Binary files ") and line.endswith(" differ"):
            tail = line[len("Binary files "):-len(" differ")].rsplit(" and ", 1)[-1]
            report.unread.append((f"{label}:{tail[2:] if tail.startswith('b/') else tail}",
                                  "binary diff, not read"))
        elif line.startswith("GIT binary patch"):
            report.unread.append((f"{label}:(binary patch)", "binary diff, not read"))
    for fname, lineno, content in parse_added(diff_text):
        is_vault = bool(fname and real(os.path.join(root, fname)) in vault)
        # A vault file is scenery when you look AT the folder (`check`: the keys live
        # there, saying so every time is noise) and an event when it is LEAVING (a commit
        # or a push). Acknowledged unread items follow the same rule: `check` accepts
        # them, the hooks never do. Anything on its way out is an event, never scenery.
        if is_vault and exempt_vault:
            continue
        loc = f"{label}:{fname or '(unknown file)'}"
        for hit in scan_line(content, registry, suspect):
            report.add(loc, lineno, hit)
            if is_vault and loc not in report.vault_leaving:
                report.vault_leaving.append(loc)


def scan_git_paths(label, raw, registry, suspect, report):
    """Paths from a NUL-separated git listing (no quoting to undo), each scanned as a NAME."""
    for p in raw.split(b"\0"):
        if not p:
            continue
        try:
            text = p.decode("utf-8")
        except UnicodeDecodeError:
            report.unread.append((f"{label}: (a path that is not valid UTF-8)", "path not fully read"))
            text = p.decode("utf-8", "replace")
        report.scan_path(f"{label}:", text, registry, suspect)


def run_pre_commit(root, vault, registry, suspect, report):
    r = git(root, "diff", "--cached", "--unified=0", "--no-color", "--no-ext-diff", "--no-textconv")
    if r.returncode != 0:
        raise GuardError(f"`git diff --cached` failed with status {r.returncode}; is {root} a git repository?")
    scan_diff("staged", decode_or_note(r.stdout, "staged diff", report), root, vault, registry, suspect, report)
    # Names are content too: a path being committed can itself be the credential. A deletion
    # sends no name, so it is left out (deleting a badly named file is the cure).
    n = git(root, "diff", "--cached", "--name-only", "-z", "--no-renames", "--diff-filter=d", "--no-ext-diff")
    if n.returncode != 0:
        raise GuardError(f"`git diff --cached --name-only` failed with status {n.returncode}.")
    scan_git_paths("staged", n.stdout, registry, suspect, report)


def scan_tag_chain(root, oid, registry, suspect, report, seen):
    """Scan the body of the annotated tag `oid` and of every tag it points at, BEFORE peeling to a
    commit (the peeled commit never shows the tag's own message). `seen` stops a loop."""
    cur = oid
    while cur and cur not in seen:
        seen.add(cur)
        t = git(root, "cat-file", "-t", cur)
        if t.returncode != 0:
            report.unread.append((f"object {cur[:10]}", "git cat-file -t failed"))
            return
        if t.stdout.decode("ascii", "replace").strip() != "tag":
            return
        label = f"tag object {cur[:10]}"
        c = git(root, "cat-file", "tag", cur)
        if c.returncode != 0:
            report.unread.append((label, "git cat-file tag failed"))
            return
        report.scan_text(f"{label} (message)", decode_or_note(c.stdout, f"{label} (message)", report),
                         registry, suspect)
        nxt = None
        for ln in c.stdout.split(b"\n\n", 1)[0].split(b"\n"):
            if ln.startswith(b"object "):
                nxt = ln[7:].strip().decode("ascii", "replace")
        if not nxt:
            report.unread.append((label, "could not read the object this tag points at"))
            return
        cur = nxt


def run_pre_push(root, vault, registry, suspect, report, stdin_text, remote=None):
    seen_refs, seen_tags = set(), set()
    for rec in stdin_text.splitlines():
        if not rec.strip():
            continue
        parts = rec.split()
        if len(parts) != 4:
            # A record that cannot be parsed is an update nobody looked at: it says so, never goes quiet.
            report.unread.append(("a push record", "could not be parsed (expected 4 fields)"))
            continue
        lref, lsha, rref, rsha = parts
        if set(lsha) == {"0"}:
            continue                                  # a delete pushes no commits and no names
        for ref in (lref, rref):                      # names are content too: both ends of every update
            if ref not in seen_refs:
                seen_refs.add(ref)
                report.scan_name(f"ref {ref}", ref, "ref", registry, suspect)
        scan_tag_chain(root, lsha, registry, suspect, report, seen_tags)
        if set(rsha) == {"0"}:
            # New branch: exclude ONLY the destination remote's refs. A key already on
            # remote A must still be caught when pushed to remote B. Without a remote
            # name, the whole history reachable from the pushed commit is checked.
            if remote:
                rl = git(root, "rev-list", lsha, "--not", f"--remotes={remote}")
            else:
                rl = git(root, "rev-list", lsha)
        else:
            rl = git(root, "rev-list", f"{rsha}..{lsha}")
        if rl.returncode != 0:
            report.unread.append((f"push of {rref}", "git rev-list could not list the outgoing commits"))
            continue
        for c in rl.stdout.decode("ascii", "replace").split():
            short = c[:10]
            cat = git(root, "cat-file", "commit", c)
            if cat.returncode != 0:
                report.unread.append((f"commit {short}", "git cat-file failed"))
            else:
                report.scan_text(f"commit {short} (message)", decode_or_note(cat.stdout, f"commit {short} (message)", report),
                                 registry, suspect)
            show = git(root, "show", "--unified=0", "--format=", "--no-color", "--no-ext-diff",
                       "--no-textconv", c)
            if show.returncode != 0:
                report.unread.append((f"commit {short}", "git show failed"))
            else:
                scan_diff(f"commit {short}", decode_or_note(show.stdout, f"commit {short} (diff)", report),
                          root, vault, registry, suspect, report)
            nm = git(root, "diff-tree", "--no-commit-id", "--name-only", "-r", "-z", "--root", "--no-renames",
                     "-m", "--diff-filter=d", c)
            if nm.returncode != 0:
                report.unread.append((f"commit {short}", "git diff-tree failed, so its paths were not read"))
            else:
                scan_git_paths(f"commit {short}", nm.stdout, registry, suspect, report)


# ---------------------------------------------------------------- main
def main(argv=None, stdin=None):
    ap = argparse.ArgumentParser(
        prog="doorman_jay.py",
        description="Stops a registered credential from leaving the machine. Never prints a value.")
    ap.add_argument("--selftest", action="store_true", help="run the built-in proof and exit")
    ap.add_argument("--remote", help="pre-push: destination remote name (the hook's $1); a new branch is "
                    "then checked against that remote's refs only")
    ap.add_argument("--repo", help="repository root (default: nearest folder at or above the current one that holds doorman.toml or .git, else here)")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("learn", help="write the registry")
    pc = sub.add_parser("check", help="check files or folders")
    pc.add_argument("paths", nargs="+")
    pa = sub.add_parser("ack", help="record that a person accepts these unread paths")
    pa.add_argument("paths", nargs="*")
    pa.add_argument("--all-unread", action="store_true", help="acknowledge everything the last check could not read")
    pa.add_argument("--reason", help="short reason written beside each acknowledgement")
    sub.add_parser("pre-commit", help="check the staged diff")
    sub.add_parser("pre-push", help="check outgoing commits (push records on stdin)")
    args = ap.parse_args(argv)
    if args.selftest:
        return selftest()
    if not args.cmd:
        ap.print_usage(sys.stderr)
        return 2
    try:
        root = resolve_root(args.repo)
        if args.cmd == "ack":
            registry = None
            try:
                registry = learn(load_config(root), root)
            except GuardError:
                pass
            run_ack(root, args.paths, args.all_unread, args.reason, registry)
            return 0
        if args.cmd in ("pre-commit", "pre-push") and not os.path.lexists(os.path.join(root, CONFIG_FILE)):
            # A REPOSITORY WITH NO doorman.toml IS ONE THIS GUARD WAS NEVER CONFIGURED FOR.
            # It does not block, and it does not go quiet: it says out loud that it is
            # installed and is checking nothing here, and it lets the operation through.
            #
            # This is NOT failing open. Failing open is claiming a safety you do not have:
            # a green light printed over a door nobody looked through. Saying plainly that
            # you are not checking is the opposite, and it is the only behaviour that lets
            # the door be installed for a whole machine (core.hooksPath), where most
            # repositories will never hold a key. A guard that refused to run in each of
            # them would be uninstalled in a week, and then it guards nothing anywhere.
            #
            # Only the two hooks get this. `check` and `learn` are typed by a person, who
            # deserves an error (exit 2, below) rather than silence. A doorman.toml that
            # EXISTS but is broken still exits 2: that repository was configured, so a
            # guard that cannot read its own config must not wave anything through.
            # The wording says "nothing was checked", never "nothing was found".
            print(f"doorman_jay: installed, but {root} has no {CONFIG_FILE}, so NOTHING WAS CHECKED here "
                  f"(this is not a clean result); to turn it on, add to {CONFIG_FILE}:  "
                  'key_files = [".env"]  Exit 0.')
            return 0
        cfg = load_config(root)
        registry = learn(cfg, root)
        print_config_exclusions(registry)
        if not registry:
            empty = ", ".join(redact(path, registry, False) for path in registry.empty_vaults)
            where = f" Empty key file(s): {empty}." if empty else ""
            raise GuardError("the vault holds no non-empty value, so there is nothing to guard. "
                             "Put NAME=value lines in the key_files." + where)

        expect = cfg.get("expect")
        if expect is not None and len(registry) != expect:
            raise GuardError(
                f"expected {expect} key(s), registered {len(registry)}. The count in "
                f"{CONFIG_FILE} and what the key files actually hold do not agree, so "
                "this guard is not watching what you think it is. Fix the key files, or "
                "correct expect, and run learn again.")
        vault = {real(p) for p in cfg["key_files"]}
        if args.cmd == "learn":
            names = sorted({redact(n, registry, False) for v in registry.values() for n in v.split(", ")})
            print(f"learned {len(registry)} key(s): {', '.join(names)}")
            print(f"registry written to {redact(os.path.join(root, REGISTRY_FILE), registry, False)} (fingerprints only)")
            print("every registered value is found wherever it appears in a line, whatever touches it "
                  "and whether or not it holds separator characters")
        if args.cmd == "learn":
            return 0
        report = Report(registry=registry, suspect=cfg["suspect"])
        if args.cmd == "check":
            report = Report(acked=read_ack(root), root=root, registry=registry, suspect=cfg["suspect"])
            check_paths([os.path.abspath(p) for p in args.paths], vault, registry, cfg["suspect"], report)
            keep = [w for w, _ in report.unread if not report.has_secret(w)]
            if not write_lastrun(root, keep):
                print(f"warning: {LASTRUN_FILE} could not be written, so `ack --all-unread` has no fresh list.")
            elif len(keep) != len(report.unread):
                print(f"warning: {len(report.unread) - len(keep)} unread item(s) carry a registered key in their "
                      f"path, so they are left out of {LASTRUN_FILE} (it must never hold a key).")
        elif args.cmd == "pre-commit":
            # STRICT ON PURPOSE: this Report takes no acknowledgements. A binary or undecodable
            # thing being committed right now is an event, not scenery.
            run_pre_commit(root, vault, registry, cfg["suspect"], report)
        elif args.cmd == "pre-push":
            # STRICT ON PURPOSE: no acknowledgements here either. A binary being pushed now is an event.
            text = (stdin if stdin is not None else sys.stdin).read()
            run_pre_push(root, vault, registry, cfg["suspect"], report, text, args.remote)
        print(report.render())
        return report.code()
    except GuardError as e:
        print(f"doorman_jay: cannot run: {e}\nExit 2.")
        return 2


# ---------------------------------------------------------------- the proof
def selftest():
    results = []

    def check(name, ok):
        results.append(bool(ok))
        print(("PASS  " if ok else "FAIL  ") + name)

    def run(argv, stdin_text=None):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            try:
                code = main(argv, stdin=io.StringIO(stdin_text) if stdin_text is not None else None)
            except SystemExit as e:
                code = e.code if isinstance(e.code, int) else 2
        return code, buf.getvalue()

    # Invented values, assembled at run time. None of these is a real credential.
    key_a = "djtest_" + "A1b2C3d4E5f6G7h8"
    key_b = "djtest_" + "Zz9Yy8Xx7Ww6Vv5U"
    key_c = "Qw3rTy7uIo9p"                      # exactly 12 characters
    key_d = "djtest_" + "M3n4O5p6Q7r8S9t0"
    short = "abcdefghijk"                       # 11 characters
    one_character = "q"
    search_minimum = "12345678"                 # exactly SEARCH_MIN characters
    real_filler = "AKIAIOSFODNN7EXAMPLE"
    standin_long = "changeme-changeme"
    standin_bracket = "${PLACEHOLDER}"
    standin_short = "xxxxxxxx"
    standin_words = "your_api_key_here"
    unreg = "sk-" + "Zq9" * 10                  # credential-shaped, never registered
    values = [key_a, key_b, key_c, key_d, short, one_character, search_minimum, real_filler, standin_long,
              standin_bracket, standin_short, standin_words, unreg]

    tmp = tempfile.mkdtemp(prefix="doorman_selftest_")
    try:
        root = os.path.join(tmp, "repo")
        for d in ("work", "clean", "bad"):
            os.makedirs(os.path.join(root, d))

        def w(rel, text, binary=False):
            path = Path(root) / rel
            if binary:
                with open(path, "wb") as fh:
                    fh.write(text)
            else:
                with open(path, "w", encoding="utf-8", newline="\n") as fh:
                    fh.write(text)
            return str(path)

        w("doorman.toml", 'key_files = [".env"]\nsuspect = false\n')
        vault = w(".env", f'# vault\nAPI_ONE="{key_a}"\nexport TOKEN_TWO={key_b}\n'
                          f'EXACT_TWELVE={key_c}\nKEY_FOUR={key_d}\nSHORT_ONE={short}\nONE_CHARACTER={one_character}\n'
                          f'EXACT_SEARCH_MIN={search_minimum}\n'
                          f'REAL_FILLER={real_filler}\nSTANDIN_LONG={standin_long}\n'
                          f'STANDIN_BRACKET={standin_bracket}\nSTANDIN_SHORT={standin_short}\n'
                          f'STANDIN_WORDS={standin_words}\nEMPTY_ONE=\n')
        notes = w("work/notes.txt", f"remember {key_a} for later\n")
        cmd = w("work/cmd.txt", f'curl -sS -H "X-Api-Key: {key_b}" "https://api.example.test/v1?x=1"\n')
        unregf = w("work/unreg.txt", f"token = {unreg}\n")
        shortf = w("work/short.txt", f"{short}\n")
        okf = w("clean/ok.txt", "nothing to see here\n")
        w("bad/blob.bin", b"\x80\x81\x82\xfe\xff not utf8", binary=True)
        R = ["--repo", root]

        code, out = run(R + ["learn"])
        check("learn exits 0 and names every non-empty key", code == 0 and "learned 12 key(s)" in out
              and all(n in out for n in ("API_ONE", "TOKEN_TWO", "EXACT_TWELVE", "KEY_FOUR",
                                          "SHORT_ONE", "ONE_CHARACTER", "EXACT_SEARCH_MIN", "REAL_FILLER", "STANDIN_LONG", "STANDIN_BRACKET",
                                          "STANDIN_SHORT", "STANDIN_WORDS")))
        check("learn output holds no value", not any(v in out for v in values if len(v) >= SEARCH_MIN))
        check("learn reports empty, short, unwatched, and doubtful entries without values",
              "empty value:" in out and "EMPTY_ONE" in out
              and "short value:" in out and "SHORT_ONE" in out and "ONE_CHARACTER" in out and "STANDIN_SHORT" in out
              and "recorded but not watched value:" in out and "ONE_CHARACTER" in out
              and "doubtful value:" in out
              and all(n in out for n in ("STANDIN_LONG", "STANDIN_BRACKET", "STANDIN_SHORT", "STANDIN_WORDS"))
              and all("REAL_FILLER" not in line for line in out.splitlines() if line.startswith("doubtful value:")))
        with open(os.path.join(root, REGISTRY_FILE), encoding="utf-8") as fh:
            reg = fh.read()
        body = [l for l in reg.splitlines() if l and not l.startswith("#")]
        check("registry holds no value from any fixture", not any(v in reg for v in values))
        check("registry lines are '<64 hex>  <NAME>' and include short and doubtful values",
              len(body) == 12 and all(re.match(r"^[0-9a-f]{64}  \w+$", l) for l in body)
              and all(n in reg for n in ("SHORT_ONE", "STANDIN_LONG", "STANDIN_BRACKET",
                                          "STANDIN_SHORT", "STANDIN_WORDS", "REAL_FILLER", "ONE_CHARACTER", "EXACT_SEARCH_MIN")))
        check("no temp file left behind by the registry write",
              not [f for f in os.listdir(root) if f.endswith(".tmp")])

        code, out = run(R + ["check", notes])
        check("registered key in a file is found and named",
              code == 1 and "API_ONE" in out and f"({len(key_a)} characters)" in out and "notes.txt:1" in out)
        check("report never holds a value or a piece of one",
              not any(v in out for v in values if len(v) >= SEARCH_MIN) and key_a[:8] not in out and key_a[-4:] not in out)
        code, out = run(R + ["check", cmd])
        check("same key inside a longer command line is found", code == 1 and "TOKEN_TWO" in out)
        code, out = run(R + ["check", unregf])
        check("unregistered credential-shaped string is NOT found while the switch is off",
              code == 0 and "FOUND" not in out and "SUSPECT" not in out)
        code, out = run(R + ["check", vault])
        check("the vault file itself is never a finding", code == 0 and "FOUND" not in out)
        code, out = run(R + ["check", shortf])
        check("a value under 12 characters is learned and found", code == 1 and "SHORT_ONE" in out)
        code, out = run(R + ["check", w("work/one-character.txt", one_character * 80 + "\n")])
        check("a one-character value is recorded but not watched", code == 0 and "FOUND" not in out)
        code, out = run(R + ["check", w("work/search-minimum.txt", search_minimum + "\n")])
        check("a value of exactly SEARCH_MIN characters is learned and found", code == 1 and "EXACT_SEARCH_MIN" in out)
        code, out = run(R + ["check", w("work/standin.txt", f"{standin_long}\n")])
        check("a stand-in is learned and found", code == 1 and "STANDIN_LONG" in out)
        code, out = run(R + ["check", w("work/exact.txt", f"{key_c}\n")])
        check("a value of exactly 12 characters is learned and found", code == 1 and "EXACT_TWELVE" in out)

        markdown_colon = "djmarkdown_" + "ColonA1b2C3d4E5"
        markdown_arrow = "djmarkdown_" + "ArrowF6g7H8i9J0"
        markdown_noted = "djmarkdown_" + "NotedK1l2M3n4O5"
        markdown_outside = "djmarkdown_" + "OutsideP6q7R8s9"
        markdown = w("inventory.md", f"""Outside Key: {markdown_outside}
```
SUPABASE URL: {markdown_colon}
WORKER ADMIN SECRET → {markdown_arrow}
NOTED ENTRY: {markdown_noted} (read+write) active
ANON KEY: (in Cloudflare Worker secrets, not in logs)
  continuation of the note
```
""")
        w("doorman.toml", 'key_files = ["inventory.md"]\nsuspect = false\n')
        code, out = run(R + ["learn"])
        check("Markdown fence: colon entry is learned and found in an ordinary file",
              code == 0 and "SUPABASE URL" in out
              and run(R + ["check", w("work/markdown-colon.txt", markdown_colon + "\n")])[0] == 1)
        check("Markdown fence: arrow entry is learned and found in an ordinary file",
              run(R + ["check", w("work/markdown-arrow.txt", markdown_arrow + "\n")])[0] == 1)
        code, out = run(R + ["check", w("work/markdown-outside.txt", markdown_outside + "\n")])
        check("Markdown form outside a code fence is ignored", code == 0 and "FOUND" not in out)
        code, out = run(R + ["learn"])
        check("Markdown trailing text registers only its first token and warns with the entry name",
              "warning: took only the first token from 1 Markdown entry(s): NOTED ENTRY" in out
              and run(R + ["check", w("work/markdown-noted.txt", markdown_noted + "\n")])[0] == 1)
        check("Markdown note values are ignored and counted separately",
              "ignored 1 Markdown note entry(s)" in out and "ANON KEY" not in out)
        empty_vault = w("empty-vault.md", "# no entries here\n")
        w("doorman.toml", 'key_files = ["empty-vault.md"]\nsuspect = false\n')
        code, out = run(R + ["learn"])
        check("an empty key file is named when there is nothing to learn",
              code == 2 and os.path.basename(empty_vault) in out)
        w("doorman.toml", 'key_files = [".env"]\nsuspect = false\n')
        code, out = run(R + ["learn"])
        check("ordinary NAME=value entries are still learned", code == 0 and "API_ONE" in out)

        public_value = "support@example.test"
        w(".env", f"API_ONE={key_a}\nSUPPORT_EMAIL={public_value}\n")
        w("doorman.toml", 'key_files = [".env"]\nconfig_names = [" SUPPORT_EMAIL "]\n')
        code, out = run(R + ["learn"])
        check("config_names excludes a named entry and says so", code == 0
              and "excluded 1 config entry(s): SUPPORT_EMAIL" in out and public_value not in out)
        public_copy = w("work/public-config.txt", public_value + "\n")
        key_copy = w("work/real-key.txt", key_a + "\n")
        public_code, public_out = run(R + ["check", public_copy])
        key_code, key_out = run(R + ["check", key_copy])
        check("a configured public value passes while a real key is still found",
              public_code == 0 and "FOUND" not in public_out and key_code == 1 and "API_ONE" in key_out)
        w("doorman.toml", 'key_files = [".env"]\n')
        run(R + ["learn"])
        with open(os.path.join(root, REGISTRY_FILE), encoding="utf-8") as fh:
            registered_before_exclusion = fh.read()
        w("doorman.toml", 'key_files = [".env"]\nconfig_names = ["SUPPORT_EMAIL"]\n')
        run(R + ["learn"])
        with open(os.path.join(root, REGISTRY_FILE), encoding="utf-8") as fh:
            registered_after_exclusion = fh.read()
        check("a later config_names exclusion removes an old registry entry",
              "SUPPORT_EMAIL" in registered_before_exclusion and "SUPPORT_EMAIL" not in registered_after_exclusion)
        w("doorman.toml", 'key_files = [".env"]\nconfig_names = ["SUPPORT_EMAIL", "MISSPELLED_NAME"]\n')
        code, out = run(R + ["learn"])
        check("a config_names entry absent from every key file is reported by name",
              code == 0 and "MISSPELLED_NAME" in out and "not found in any key file" in out)
        embedded_name = "NOTE_" + key_a
        missing_embedded_name = "MISSING_" + key_a
        w(".env", f"API_ONE={key_a}\n{embedded_name}=ordinary configuration\n")
        w("doorman.toml", f'key_files = [".env"]\nconfig_names = ["{embedded_name}", "{missing_embedded_name}"]\n')
        code, out = run(R + ["learn"])
        check("learn redacts a registered value embedded in an excluded config_names entry",
              code == 0 and "excluded 1 config entry(s): NOTE_<redacted>" in out
              and key_a not in out and key_a[:8] not in out)
        check("learn redacts a registered value embedded in a missing config_names entry",
              "config_names not found in any key file: MISSING_<redacted>" in out
              and key_a not in out and key_a[:8] not in out)
        w(".env", f"api_key={public_value}\nAPI_KEY={key_a}\n")
        w("doorman.toml", 'key_files = [".env"]\nconfig_names = ["api_key"]\n')
        code, out = run(R + ["learn"])
        case_copy = w("work/case-key.txt", key_a + "\n")
        case_code, case_out = run(R + ["check", case_copy])
        check("config_names matches exactly: api_key leaves API_KEY registered",
              code == 0 and case_code == 1 and "API_KEY" in case_out)
        check("check reports how many config entries are excluded",
              "excluded 1 config entry(s): api_key" in case_out)
        w("doorman.toml", 'key_files = [".env"]\nsuspect = false\n')
        w(".env", f'# vault\nAPI_ONE="{key_a}"\nexport TOKEN_TWO={key_b}\n'
                  f'EXACT_TWELVE={key_c}\nSHORT_ONE={short}\n')

        code, out = run(R + ["check", okf])
        check("exit 0: nothing found, everything read", code == 0 and "everything was read" in out)
        code, out = run(R + ["check", notes])
        check("exit 1: a registered key was found", code == 1)
        empty = os.path.join(tmp, "empty")
        os.makedirs(empty)
        code, out = run(["--repo", empty, "check", okf])
        check("exit 2: config missing, and the output says what to write",
              code == 2 and "doorman.toml" in out and "key_files" in out)
        code, out = run(["--repo", empty, "pre-commit"])
        check("pre-commit with no config: exit 0, says it is checking nothing, never says clean",
              code == 0 and "NOTHING WAS CHECKED" in out and "doorman.toml" in out
              and 'key_files = [".env"]' in out and "clean." not in out and "Nothing found" not in out)
        zero40 = "0" * 40
        code, out = run(["--repo", empty, "pre-push"], f"refs/heads/main {'1' * 40} refs/heads/main {zero40}\n")
        check("pre-push with no config: exit 0, says it is checking nothing, never says clean",
              code == 0 and "NOTHING WAS CHECKED" in out and "clean." not in out and "Nothing found" not in out)
        code, out = run(["--repo", empty, "check", okf])
        check("check with no config still exits 2 with the message it always had",
              code == 2 and "was not found" in out and "key_files" in out)
        code, out = run(["--repo", empty, "learn"])
        check("learn with no config still exits 2", code == 2 and "was not found" in out)
        code, out = run(R + ["check", os.path.join(root, "bad")])
        check("exit 3: nothing found but a file could not be decoded; says 'not a clean result'",
              code == 3 and "not a clean result" in out.lower() and "NOT READ" in out)
        os.makedirs(os.path.join(root, "gitlike", ".git"))
        w("gitlike/.git/config", f"token = {key_a}\n")
        code, out = run(R + ["check", os.path.join(root, "gitlike")])
        check("exit 3: a pruned .git folder is recorded as not read, not as clean",
              code == 3 and "NOT READ" in out and ".git" in out)
        code, out = run(R + ["check", os.path.join(root, "nope")])
        check("exit 3: a path that does not exist counts as not read", code == 3)

        # acknowledged-unread
        unr = os.path.join(root, "unr")
        os.makedirs(unr)
        w("unr/t.txt", "plain text\n")
        w("unr/a.bin", b"\x89PNG\xff\xfe\x00 a", binary=True)
        w("unr/b.bin", b"%PDF\xff\xfe\x00 b", binary=True)
        ackp = os.path.join(root, ACK_FILE)
        code, out = run(R + ["check", unr])
        check("ack setup: an unacknowledged unread item gives exit 3", code == 3 and out.count("NOT READ ") == 2)
        code, out = run(R + ["ack", "--all-unread", "--reason", "known binary"])
        expect = {sha("unr/a.bin"), sha("unr/b.bin")}
        got = set(read_ack(root))
        check("ack --all-unread adds exactly the items of the previous run",
              code == 0 and "2 added, 0 already there" in out and got == expect)
        code, out = run(R + ["ack", "--all-unread"])
        check("ack --all-unread twice adds nothing new", code == 0 and "0 added, 2 already there" in out)
        code, out = run(R + ["check", unr])
        check("an acknowledged unread item gives exit 0 and is still counted and printed",
              code == 0 and "2 item(s) were not read but are acknowledged" in out
              and "NOT READ, ACKNOWLEDGED" in out and "a.bin" in out and "a person accepted" in out)
        code, out = run(R + ["check", unr])
        check("a content-bound acknowledgement remains accepted while its unread file is unchanged",
              code == 0 and "2 item(s) were not read but are acknowledged" in out)
        w("unr/b.bin", b"\x89PNG\xff\xfe\x00 replaced", binary=True)
        code, out = run(R + ["check", unr])
        check("replacing an acknowledged unread file reopens it and says its content changed",
              code == 3 and "b.bin" in out and "content changed since it was acknowledged" in out)
        w("unr/b.bin", b"%PDF\xff\xfe\x00 b", binary=True)
        with open(ackp, encoding="utf-8") as fh:
            ack_text = fh.read()
        legacy = [f"{sha('unr/b.bin')}  2026-01-01  old acceptance" if l.startswith(sha("unr/b.bin")) else l
                  for l in ack_text.splitlines()]
        w(ACK_FILE, "\n".join(legacy) + "\n")
        w("unr/b.bin", b"\x89PNG\xff\xfe\x00 replaced again", binary=True)
        code, out = run(R + ["check", unr])
        check("a legacy three-field acknowledgement still accepts by path and reports its count",
              code == 0 and "1 acknowledged item(s) use the legacy three-field format" in out)
        w("unr/b.bin", b"%PDF\xff\xfe\x00 b", binary=True)
        w(ACK_FILE, ack_text)
        w("unr/c.bin", b"\xff\xfe\x00 c", binary=True)
        code, out = run(R + ["check", unr])
        check("an unacknowledged unread item still gives exit 3, beside acknowledged ones",
              code == 3 and "NOT READ " in out and "c.bin" in out and "2 item(s) were not read but are acknowledged" in out)
        os.remove(os.path.join(unr, "c.bin"))
        with open(ackp, encoding="utf-8") as fh:
            ack_text = fh.read()
        ack_body = [l for l in ack_text.splitlines() if l and not l.startswith("#")]
        check("the ack file holds hashes, dates and reasons and no raw path",
              len(ack_body) == 2 and all(re.match(r"^[0-9a-f]{64}  [0-9a-f]{64}  \d{4}-\d\d-\d\d  known binary$", l) for l in ack_body)
              and "a.bin" not in ack_text and "unr/" not in ack_text and root not in ack_text
              and "could NOT read" in ack_text)
        code, out = run(R + ["check", ackp])
        check("the ack file is checked like any other file", code == 0 and "everything was read" in out)
        kept = [l for l in ack_text.splitlines() if not l.startswith(sha("unr/a.bin"))]
        w(ACK_FILE, "\n".join(kept) + "\n")
        code, out = run(R + ["check", unr])
        check("removing a line from the ack file makes that item incomplete again",
              code == 3 and "NOT READ " in out and "a.bin" in out and "1 item(s) were not read but are acknowledged" in out)

        # ack hardening: malformed lines, empty last run, newline in a path
        w(ACK_FILE, sha("unr/a.bin") + "\n" + sha("unr/b.bin") + "  2026-01-01\n")
        check("a hash line with no date and reason is not an acknowledgement", read_ack(root) == {})
        code, out = run(R + ["check", unr])
        check("a malformed ack line does not silence an unread item",
              code == 3 and "acknowledged" not in out)
        w(ACK_FILE, "\n".join(kept) + "\n")
        os.makedirs(os.path.join(root, "empty"))
        w("empty/t.txt", "plain\n")
        run(R + ["check", os.path.join(root, "empty")])
        code, out = run(R + ["ack", "--all-unread"])
        check("ack --all-unread after a run with zero unread items succeeds, 0 added",
              code == 0 and "0 added, 0 already there" in out)
        check("write_lastrun keeps a path containing a newline",
              write_lastrun(root, ["odd\nname.bin", "plain.bin"]))
        code, out = run(R + ["ack", "--all-unread"])
        check("ack --all-unread adds a newline-containing path too (2 added)",
              code == 0 and "2 added" in out and sha(rel_key(os.path.abspath("odd\nname.bin"), root)) in read_ack(root))
        missing = os.path.join(root, "no-own-bytes")
        code, out = run(R + ["ack", missing, "--reason", "known missing path"])
        code2, out2 = run(R + ["check", missing])
        check("an item without its own bytes is acknowledged with '-' and remains accepted",
              code == 0 and read_ack(root)[sha(rel_key(missing, root))][0] == "-" and code2 == 0
              and "NOT READ, ACKNOWLEDGED" in out2)

        # symlink / junction: not followed, recorded as not read
        holder = os.path.join(tmp, "holder")
        target = os.path.join(tmp, "target")
        os.makedirs(holder)
        os.makedirs(target)
        with open(os.path.join(target, "k.txt"), "w", encoding="utf-8") as fh:
            fh.write(key_a + "\n")
        link = os.path.join(holder, "lnk")
        made = False
        try:
            os.symlink(target, link, target_is_directory=True)
            made = True
        except (OSError, NotImplementedError):
            if os.name == "nt":
                r = subprocess.run(["cmd", "/c", "mklink", "/J", link, target], capture_output=True)
                made = r.returncode == 0
        if made:
            code, out = run(R + ["check", holder])
            check("a symlink/junction directory is not followed and is recorded as not read",
                  code == 3 and "symlink or junction" in out and "FOUND" not in out)
        else:
            print("SKIP  symlink/junction check (this account could not create a link)")

        # git hooks
        if shutil.which("git"):
            g = os.path.join(tmp, "grepo")
            os.makedirs(g)
            gi = ["git", "-C", g, "-c", "user.name=t", "-c", "user.email=t@example.test",
                  "-c", "commit.gpgsign=false"]
            subprocess.run(["git", "-C", g, "init", "-q"], capture_output=True)
            for name, text in (("doorman.toml", 'key_files = [".env"]\nconfig_names = ["EXCLUDED_NOTE"]\n'),
                               (".env", f"GIT_KEY={key_a}\nEXCLUDED_NOTE=ordinary configuration\n"),
                               ("clean.txt", "hello world\n")):
                with open(os.path.join(g, name), "w", encoding="utf-8") as fh:
                    fh.write(text)
            GR = ["--repo", g]
            subprocess.run(gi + ["add", "clean.txt"], capture_output=True)
            code, out = run(GR + ["pre-commit"])
            check("pre-commit: a clean staged diff exits 0 and reports one excluded entry",
                  code == 0 and "excluded 1 config entry(s): EXCLUDED_NOTE" in out)
            subprocess.run(gi + ["commit", "-q", "-m", "clean"], capture_output=True)
            clean_sha = subprocess.run(gi + ["rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
            with open(os.path.join(g, "leak.txt"), "w", encoding="utf-8") as fh:
                fh.write(f"line one\nexport X={key_a}\n")
            subprocess.run(gi + ["add", "leak.txt", ".env"], capture_output=True)
            code, out = run(GR + ["pre-commit"])
            check("configured repository: the same staged key is still stopped (exit 1, no notice of skipping)",
                  code == 1 and "NOTHING WAS CHECKED" not in out and key_a not in out)
            ng = os.path.join(tmp, "norepo")
            os.makedirs(ng)
            subprocess.run(["git", "-C", ng, "init", "-q"], capture_output=True)
            with open(os.path.join(ng, "leak.txt"), "w", encoding="utf-8") as fh:
                fh.write(f"export X={key_a}\n")
            subprocess.run(["git", "-C", ng, "add", "leak.txt"], capture_output=True)
            code, out = run(["--repo", ng, "pre-commit"])
            check("unconfigured git repository holding a staged key: passes, and says nothing was checked",
                  code == 0 and "NOTHING WAS CHECKED" in out and key_a not in out)
            # a nested repository must not borrow the config of the repository around it
            nest = os.path.join(g, "nested")
            os.makedirs(nest)
            subprocess.run(["git", "-C", nest, "init", "-q"], capture_output=True)
            here = os.getcwd()
            try:
                os.chdir(nest)
                found = resolve_root(None)
            finally:
                os.chdir(here)
            check("nested repository: the nearest .git wins over an outer doorman.toml",
                  os.path.realpath(found) == os.path.realpath(nest))
            # a doorman.toml that exists but is not a regular file is a broken config: exit 2
            bd = os.path.join(tmp, "dirconf")
            os.makedirs(os.path.join(bd, CONFIG_FILE))
            code, out = run(["--repo", bd, "pre-commit"])
            check("doorman.toml that is a directory: pre-commit exits 2, not 0",
                  code == 2 and "not a regular file" in out and "NOTHING WAS CHECKED" not in out)
            code, out = run(["--repo", bd, "pre-push"], f"refs/heads/main {'1' * 40} refs/heads/main {'0' * 40}\n")
            check("doorman.toml that is a directory: pre-push exits 2, not 0", code == 2)
            code, out = run(GR + ["pre-commit"])
            findings = [l for l in out.splitlines() if l.startswith("FOUND")]
            check("pre-commit: a staged registered key exits 1 with file:line; the staged vault is a finding too",
                  code == 1 and len(findings) == 2 and any("leak.txt:2" in f for f in findings)
                  and any(".env:1" in f for f in findings)
                  and all("GIT_KEY" in f for f in findings) and key_a not in out)
            check("pre-commit: the force-added vault says plainly it is the key store leaving",
                  "key store itself leaving the repository" in out and "almost certainly a mistake" in out)
            # vault at the door: stopped by pre-commit, and never printed
            gv = os.path.join(tmp, "vrepo")
            os.makedirs(gv)
            giv = ["git", "-C", gv, "-c", "user.name=t", "-c", "user.email=t@example.test",
                   "-c", "commit.gpgsign=false"]
            subprocess.run(["git", "-C", gv, "init", "-q"], capture_output=True)
            for name, text in (("doorman.toml", 'key_files = [".env"]\n'),
                               (".env", f"VAULT_KEY={key_a}\n"), ("seed.txt", "hello\n")):
                with open(os.path.join(gv, name), "w", encoding="utf-8", newline="\n") as fh:
                    fh.write(text)
            GV = ["--repo", gv]
            subprocess.run(giv + ["add", "seed.txt", "doorman.toml"], capture_output=True)
            subprocess.run(giv + ["commit", "-q", "-m", "seed"], capture_output=True)
            seed_sha = subprocess.run(giv + ["rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
            subprocess.run(giv + ["add", "-f", ".env"], capture_output=True)
            code, out = run(GV + ["pre-commit"])
            check("pre-commit: a force-added vault file holding a registered key exits 1",
                  code == 1 and "VAULT_KEY" in out and "key store itself leaving" in out)
            check("pre-commit: the vault finding prints no character of the value",
                  key_a not in out and key_a[:8] not in out and key_a[-4:] not in out)
            subprocess.run(giv + ["commit", "-q", "-m", "oops"], capture_output=True)
            vsha = subprocess.run(giv + ["rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
            code, out = run(GV + ["pre-push"], f"refs/heads/main {vsha} refs/heads/main {seed_sha}\n")
            check("pre-push: the same force-added vault file exits 1",
                  code == 1 and "VAULT_KEY" in out and "key store itself leaving" in out)
            check("pre-push: the vault finding prints no character of the value",
                  key_a not in out and key_a[:8] not in out and key_a[-4:] not in out)
            code, out = run(GV + ["check", os.path.join(gv, ".env"), os.path.join(gv, "seed.txt"), os.path.join(gv, "doorman.toml")])
            check("filesystem check of that folder: the vault is still exempt (exit 0)",
                  code == 0 and "FOUND" not in out and "VAULT" not in out)
            with open(os.path.join(gv, "copy.txt"), "w", encoding="utf-8", newline="\n") as fh:
                fh.write(f"X={key_a}\n")
            subprocess.run(giv + ["add", "copy.txt"], capture_output=True)
            code, out = run(GV + ["pre-commit"])
            check("a non-vault file holding the same key is still stopped",
                  code == 1 and "copy.txt:1" in out and key_a not in out)
            subprocess.run(gi + ["commit", "-q", "-m", "oops"], capture_output=True)
            bad_sha = subprocess.run(gi + ["rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
            code, out = run(GR + ["pre-push"], f"refs/heads/main {bad_sha} refs/heads/main {clean_sha}\n")
            check("pre-push: an outgoing commit holding a registered key exits 1",
                  code == 1 and "GIT_KEY" in out and key_a not in out)
            code, out = run(GR + ["pre-push"], f"refs/heads/main {clean_sha} refs/heads/main {clean_sha}\n")
            check("pre-push: nothing outgoing exits 0", code == 0)
            zero = "0" * 40
            subprocess.run(gi + ["update-ref", "refs/remotes/remoteA/main", bad_sha], capture_output=True)
            code, out = run(GR + ["--remote", "remoteB", "pre-push"], f"refs/heads/x {bad_sha} refs/heads/x {zero}\n")
            check("pre-push: a key already on remote A is caught when pushed to remote B", code == 1 and "GIT_KEY" in out)
            code, out = run(GR + ["--remote", "remoteA", "pre-push"], f"refs/heads/x {bad_sha} refs/heads/x {zero}\n")
            check("pre-push: commits already on the destination remote are skipped", code == 0)
            code, out = run(GR + ["pre-push"], f"refs/heads/x {bad_sha} refs/heads/x {zero}\n")
            check("pre-push: new branch without a remote name checks the whole history", code == 1)
            with open(os.path.join(g, "pic.bin"), "wb") as fh:
                fh.write(b"\x00\x01\x02\xff\xfe binary")
            subprocess.run(gi + ["add", "pic.bin"], capture_output=True)
            code, out = run(GR + ["pre-commit"])
            check("exit 3: a staged binary file is recorded as not read", code == 3 and "binary diff, not read" in out)
            code, out = run(GR + ["ack", os.path.join(g, "pic.bin")])
            check("ack of the staged binary is recorded", code == 0 and "1 added" in out)
            code, out = run(GR + ["check", os.path.join(g, "pic.bin")])
            check("check honours that acknowledgement (exit 0, still counted)",
                  code == 0 and "1 item(s) were not read but are acknowledged" in out)
            code, out = run(GR + ["pre-commit"])
            check("an acknowledgement does NOT silence the same item in pre-commit",
                  code == 3 and "binary diff, not read" in out and "acknowledged" not in out)
        else:
            print("SKIP  git hook checks (git is not on PATH)")

        # the switch
        w("doorman.toml", 'key_files = [".env"]\nsuspect = true\n')
        code, out = run(R + ["check", unregf])
        check("switch on: the unregistered credential-shaped string is reported as SUSPECT (exit 1)",
              code == 1 and "SUSPECT" in out and unreg not in out)
        w("doorman.toml", 'key_files = [".env"]\nsuspect = false\n')

        # rotation: no action needed, the next run re-learns
        key_a2 = "djtest_" + "Rot4ted9Key7Zz3"
        values.append(key_a2)
        w(".env", f'API_ONE="{key_a2}"\n')
        code, out = run(R + ["check", notes])
        check("rotated key: the old value is no longer registered after the next run", code == 0)
        code, out = run(R + ["check", w("work/new.txt", f"{key_a2}\n")])
        check("rotated key: the new value is found with no extra step", code == 1 and "API_ONE" in out)
        with open(os.path.join(root, REGISTRY_FILE), encoding="utf-8") as fh:
            reg = fh.read()
        check("registry still holds no value after rotation", not any(v in reg for v in values))

        # ---- the key wherever it sits (by length), and names are content too
        wk_p = "djwin_" + "P1q2R3s4T5u6V7w8"          # plain value, 22 characters
        wk_s = "djwin/" + "Ab12Cd34=Ef56Gh78="         # holds "/" and "=", 24 characters
        wvals = [wk_p, wk_s]

        def clean_out(out):
            return not any(v in out for v in wvals) and wk_p[:8] not in out and wk_s[:8] not in out

        nr = os.path.join(tmp, "nrepo")
        os.makedirs(nr)

        def nw(rel, text):
            path = os.path.join(nr, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text)
            return path

        nw("doorman.toml", 'key_files = [".env"]\n')
        nw(".env", f"PLAIN_KEY={wk_p}\nSLASH_KEY={wk_s}\n")
        N = ["--repo", nr]
        code, out = run(N + ["learn"])
        check("learn: two keys named, no value printed, and no claim that a separator hides a key",
              code == 0 and "learned 2 key(s)" in out and "cannot see them whole" not in out
              and "wherever it appears" in out and clean_out(out))
        for label, text, name in (
                ("a key inside a Markdown code span with backticks", f"use `{wk_p}` here\n", "PLAIN_KEY"),
                ("a key followed by a full stop", f"the key is {wk_p}.\n", "PLAIN_KEY"),
                ("a key followed by #note", f"x = {wk_p}#note\n", "PLAIN_KEY"),
                ("a key glued to letters before and after", f"abc{wk_p}xyz\n", "PLAIN_KEY"),
                ("a key inside Bearer-<key>", f"Authorization: Bearer-{wk_p}\n", "PLAIN_KEY"),
                ("a registered value holding / and =", f"x {wk_s} y\n", "SLASH_KEY"),
                ("a registered value holding / and =, before a full stop", f"({wk_s}).\n", "SLASH_KEY"),
                ("a key in a 200 KB line with no other key-like text (pre-scan path)",
                 "x" * 100000 + wk_p + "y" * 100000 + "\n", "PLAIN_KEY"),
                ("a key at the end of a line packed with its own first characters (rolling-walk path)",
                 "djwin_" * 30000 + wk_p + "\n", "PLAIN_KEY")):
            code, out = run(N + ["check", nw("t/c.txt", text)])
            check("window matcher: " + label + " is found and nothing of it is printed",
                  code == 1 and name in out and clean_out(out))
        for label, text in (("ordinary text with a code span, a Bearer word and a full stop",
                             "use `code` here, Bearer-token abc. djwin is a word. a/b=c#note\n"),
                            ("a near miss with the last character changed", f"{wk_p[:-1]}X and {wk_s[:-1]}Y\n"),
                            ("a value one character too short", f"{wk_p[:-1]}\n")):
            code, out = run(N + ["check", nw("t/c.txt", text)])
            check("window matcher control: " + label + " is clean", code == 0 and "FOUND" not in out)

        nw("named/" + wk_p + ".txt", "plain content\n")
        code, out = run(N + ["check", os.path.join(nr, "named")])
        check("check: a file whose NAME is the key is found, says it is in the NAME of a path, prints nothing of it",
              code == 1 and "NAME of a path" in out and "PLAIN_KEY" in out and "<redacted>" in out and clean_out(out))
        nw("fine/ordinary_name.txt", "plain content\n")
        code, out = run(N + ["check", os.path.join(nr, "fine")])
        check("check control: an ordinarily named file is clean", code == 0 and "FOUND" not in out)
        nw("dirs/" + wk_p + "/one.txt", "a\n")
        nw("dirs/" + wk_p + "/two.txt", "b\n")
        code, out = run(N + ["check", os.path.join(nr, "dirs")])
        check("check: a folder named with the key is ONE finding, not one per file",
              code == 1 and len([l for l in out.splitlines() if l.startswith("FOUND")]) == 1
              and "NAME of a path" in out and clean_out(out))
        nw("both/" + wk_p + ".txt", f"{wk_p}\n")
        code, out = run(N + ["check", os.path.join(nr, "both")])
        check("check: a file named with the key AND holding it never prints the key in its location",
              code == 1 and clean_out(out) and "both" in out)
        code, out = run(N + ["check", os.path.join(nr, "t", "..", "fine")])
        check("check control: a path with .. in it is clean", code == 0)

        if shutil.which("git"):
            gn = os.path.join(tmp, "nname")
            os.makedirs(gn)
            gnc = ["git", "-C", gn, "-c", "user.name=t", "-c", "user.email=t@example.test",
                   "-c", "commit.gpgsign=false"]
            subprocess.run(["git", "-C", gn, "init", "-q"], capture_output=True)
            for name, text in (("doorman.toml", 'key_files = [".env"]\n'), (".env", f"PLAIN_KEY={wk_p}\n"),
                               ("c.txt", "hello world\n")):
                with open(os.path.join(gn, name), "w", encoding="utf-8", newline="\n") as fh:
                    fh.write(text)
            GN = ["--repo", gn]
            zero = "0" * 40
            subprocess.run(gnc + ["add", "c.txt"], capture_output=True)
            code, out = run(GN + ["pre-commit"])
            check("names control: a clean staged file passes pre-commit", code == 0 and "FOUND" not in out)
            subprocess.run(gnc + ["commit", "-q", "-m", "clean"], capture_output=True)
            base = subprocess.run(gnc + ["rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
            with open(os.path.join(gn, wk_p + ".txt"), "w", encoding="utf-8", newline="\n") as fh:
                fh.write("ordinary content\n")
            subprocess.run(gnc + ["add", wk_p + ".txt"], capture_output=True)
            code, out = run(GN + ["pre-commit"])
            check("pre-commit: a staged file whose NAME is the key stops (exit 1), says NAME of a path, prints nothing of it",
                  code == 1 and "NAME of a path" in out and "PLAIN_KEY" in out and clean_out(out))
            subprocess.run(gnc + ["commit", "-q", "-m", "named"], capture_output=True)
            named = subprocess.run(gnc + ["rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
            code, out = run(GN + ["pre-push"], f"refs/heads/main {named} refs/heads/main {base}\n")
            check("pre-push: an outgoing commit that adds a file named with the key stops, and prints nothing of it",
                  code == 1 and "NAME of a path" in out and clean_out(out))
            subprocess.run(gnc + ["reset", "-q", "--hard", base], capture_output=True)
            code, out = run(GN + ["pre-push"], f"refs/heads/main {base} refs/heads/main {zero}\n")
            check("pre-push control: an ordinary branch and clean commit pass", code == 0 and "FOUND" not in out)
            subprocess.run(gnc + ["branch", wk_p], capture_output=True)
            code, out = run(GN + ["pre-push"], f"refs/heads/{wk_p} {base} refs/heads/{wk_p} {zero}\n")
            check("pre-push: a branch whose NAME is the key stops, says NAME of a ref, prints nothing of it",
                  code == 1 and "NAME of a ref" in out and "PLAIN_KEY" in out and clean_out(out))
            code, out = run(GN + ["pre-push"], f"refs/heads/main {base} refs/heads/{wk_p} {zero}\n")
            check("pre-push: a key only in the DESTINATION ref name stops too",
                  code == 1 and "NAME of a ref" in out and clean_out(out))
            code, out = run(GN + ["pre-push"], f"(delete) {zero} refs/heads/{wk_p} {base}\n")
            check("pre-push: deleting the badly named branch is not stopped", code == 0)
            code, out = run(GN + ["pre-push"], "refs/heads/main\n")
            check("pre-push: a record that cannot be parsed is not called clean (exit 3)",
                  code == 3 and "could not be parsed" in out)
            subprocess.run(gnc + ["tag", "-a", "v1", "-m", f"release note {wk_p}"], capture_output=True)
            tag1 = subprocess.run(gnc + ["rev-parse", "v1"], capture_output=True, text=True).stdout.strip()
            code, out = run(GN + ["pre-push"], f"refs/tags/v1 {tag1} refs/tags/v1 {zero}\n")
            check("pre-push: an annotated tag whose MESSAGE holds the key stops, and prints nothing of it",
                  code == 1 and "PLAIN_KEY" in out and "tag object" in out and "(message)" in out and clean_out(out))
            subprocess.run(gnc + ["tag", "-a", "v2", "-m", "release notes, nothing secret"], capture_output=True)
            tag2 = subprocess.run(gnc + ["rev-parse", "v2"], capture_output=True, text=True).stdout.strip()
            code, out = run(GN + ["pre-push"], f"refs/tags/v2 {tag2} refs/tags/v2 {zero}\n")
            check("pre-push control: an ordinary annotated tag passes", code == 0 and "FOUND" not in out)
        else:
            print("SKIP  names in git checks (git is not on PATH)")

        label_root = os.path.join(tmp, "labelrepo")
        os.makedirs(label_root)
        label_value = "djlabel_" + "A1b2C3d4E5f6G7h8"
        label_name = "KEY_" + label_value
        with open(os.path.join(label_root, "doorman.toml"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write('key_files = [".env"]\nsuspect = false\n')
        with open(os.path.join(label_root, ".env"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(f"{label_name}={label_value}\n")
        label_leak = os.path.join(label_root, "leak.txt")
        with open(label_leak, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(label_value + "\n")
        L = ["--repo", label_root]
        code, out = run(L + ["check", label_leak])
        check("a registry NAME containing a registered value prints none of that value in a finding",
              code == 1 and label_value not in out)
        run(L + ["learn"])
        with open(os.path.join(label_root, REGISTRY_FILE), encoding="utf-8") as fh:
            label_registry = fh.read()
        check("learn writes none of a registered value embedded in a registry NAME",
              label_value not in label_registry)
        run(L + ["ack", label_leak, "--reason", "copied " + label_value + " from an error"])
        with open(os.path.join(label_root, ACK_FILE), encoding="utf-8") as fh:
            label_ack = fh.read()
        check("ack writes none of a registered value embedded in its reason",
              label_value not in label_ack)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    failed = results.count(False)
    print(f"{len(results)} checks, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
