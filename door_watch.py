#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
door_watch.py — checks that Doorman Jay is still standing.

The risk this file covers: an agent, an installer or a clean-up can delete the
hooks (or the git config line that points at them), and the door disappears
without a sound. A guard that is gone is worse than no guard, because you still
believe you have one.

🔑 Reading the configuration is not enough: that only says the files are
written. This watchman SENDS A FAKE KEY through the door, in a throwaway
repository, and checks that it really stops. That is the difference between
believing the paper and looking at the disk.

HOW THE DOOR CAN BE INSTALLED. `install.py` has three routes, and
the watchman recognises the two that act on an existing repository:
  - per repository (the recommended one): `pre-commit` and `pre-push` sit in the
    hooks folder that git itself reports for that repository
    (`git rev-parse --git-path hooks`). Recognised by the marker line
    install.py writes into every hook it generates.
  - machine-wide: `core.hooksPath` is set and points at a folder holding this
    piece's hooks.
  - the third route, the git template folder, only affects repositories created
    AFTER it was switched on; once a repository has been created from it, its
    hooks are an ordinary per-repository copy and are seen as such. A
    repository with none of this piece's hooks is "not installed here".
The key tests run against the hooks folder the repository really uses, so what
is proven is what git would run, not a distant copy.

USE
  python door_watch.py                 check the repository in the current folder
  python door_watch.py --repo <path>   check that repository instead
  python door_watch.py --brief         one line only, for a startup check

Exits 0 if the door is healthy (installed one of the two ways for that
repository, both hooks present, BOTH hooks proven), 1 if something is missing,
unproven or could not be checked. It never fixes anything: it reports, and
installing is the owner's decision.
"""
import io
import os
import sys
import argparse
import shutil
import tempfile
import subprocess

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
FAKE_KEY = "AIza" + "SyD-watch" + "0123456789abcdefghijklmno"

# The line install.py writes into every hook it generates (its
# MARKER). Copied here, not imported, so the watchman keeps working even if
# install.py is changed or missing. It is how "this piece's hook" is told apart
# from somebody else's file of the same name.
MARKER = "doorman-jay-hook:v1"
HOOKS = ("pre-commit", "pre-push")

ROUTE_REPO = "per repository"
ROUTE_MACHINE = "machine-wide"
ROUTE_NONE = "not installed here"


def _sh(args, cwd=None, stdin_text=None, env=None):
    return subprocess.run(args, cwd=cwd, input=stdin_text, env=env,
                          capture_output=True, text=True, timeout=120)


def _hook_state(folder, name):
    """(present, ours, crlf) for one hook file in `folder`."""
    p = os.path.join(folder, name)
    if not os.path.exists(p):
        return False, False, False
    try:
        raw = io.open(p, "rb").read()
    except OSError:
        return True, False, False
    return True, MARKER.encode("ascii") in raw, b"\r\n" in raw


def detect_route(repo):
    """Works out HOW the door is installed for `repo`.

    Returns (route, folder, detail):
      route  - ROUTE_REPO, ROUTE_MACHINE, ROUTE_NONE, or None when the question
               cannot be answered (not a git repository / git not runnable);
               then `detail` says why.
      folder - the hooks folder git really uses for this repository (absolute),
               or None.
    Why `git rev-parse --git-path hooks`: it is the folder git would actually
    use. It already obeys core.hooksPath, so the route is told apart by whether
    core.hooksPath is set, never by guessing `.git/hooks` (worktrees and
    submodules keep it elsewhere).
    """
    if not os.path.isdir(repo):
        return None, None, "%s is not a folder" % repo
    try:
        r = _sh(["git", "rev-parse", "--git-dir"], cwd=repo)
        if r.returncode != 0:
            return None, None, "%s is not inside a git repository" % repo
        r = _sh(["git", "rev-parse", "--git-path", "hooks"], cwd=repo)
        out = (r.stdout or "").strip()
        if r.returncode != 0 or not out:
            return None, None, "git could not say where this repository keeps its hooks"
        folder = os.path.abspath(os.path.join(repo, out))
        hp = (_sh(["git", "config", "--get", "core.hooksPath"], cwd=repo).stdout or "").strip()
    except (OSError, subprocess.SubprocessError) as e:
        return None, None, "git could not be run (%s: %s)" % (type(e).__name__, e)

    ours = [h for h in HOOKS if _hook_state(folder, h)[1]]
    if hp:
        if ours:
            return ROUTE_MACHINE, folder, "core.hooksPath = %s" % folder.replace("\\", "/")
        return ROUTE_NONE, folder, ("core.hooksPath points at %s, which holds none of "
                                    "this piece's hooks" % folder.replace("\\", "/"))
    if ours:
        return ROUTE_REPO, folder, folder.replace("\\", "/")
    return ROUTE_NONE, folder, "no hook of this piece in %s" % folder.replace("\\", "/")


def files_in_place(route, folder):
    """Problems with the files the door needs. Empty list = all in place."""
    missing = []
    # Doorman Jay stands alone: it needs no pattern list from another file,
    # because it does not guess. It knows the house keys by their fingerprint.
    for n in ("doorman_jay.py",):
        if not os.path.exists(os.path.join(HERE, n)):
            missing.append(n + " (not there)")
    # The hooks are looked for in the folder git really uses for
    # this repository, not only in this piece's own folder: per-repository
    # installs hold COPIES. Only when the door is installed (a route exists);
    # a missing hook is named, and so is one this piece did not write.
    if route in (ROUTE_REPO, ROUTE_MACHINE):
        for n in HOOKS:
            present, ours, crlf = _hook_state(folder, n)
            if not present:
                missing.append(n + " (not there, in %s)" % folder.replace("\\", "/"))
            elif not ours:
                missing.append(n + " (there, but without this piece's marker: "
                                   "not written by install.py)")
            elif crlf:
                missing.append(n + " (has CRLF endings and /bin/sh will not start it)")
    return missing


class SetupFailed(Exception):
    """A step of the fixture failed, so the test proves nothing."""


def _must(args, cwd=None, env=None):
    """Runs a setup step and INSISTS it worked. See install.py for the why."""
    r = _sh(args, cwd=cwd, env=env)
    if r.returncode != 0:
        first = ((r.stderr or "") + (r.stdout or "")).strip().splitlines()
        raise SetupFailed("`%s` exited %d%s" % (" ".join(args[:2]), r.returncode,
                                                (": " + first[0][:90]) if first else ""))
    return r


# What the reviewer prints when it catches a key. The watchman demands these
# words, not merely a failed push: anything can fail a push.
PROOF = "registered key"


def _hermetic(tmp):
    """The environment for a throwaway-repo git command.

    GIT_CONFIG_NOSYSTEM=1 and an EMPTY file as the global config: git reads
    neither the machine's nor the user's configuration for the fixture, so a
    global core.hooksPath, hooksPath-like templates, signing or an alias cannot
    steer the test. Only the -c core.hooksPath=<folder under test> below applies.
    """
    empty = os.path.join(tmp, "empty.gitconfig")
    io.open(empty, "w", encoding="utf-8").close()
    env = dict(os.environ)
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_GLOBAL"] = empty
    return env


def _hooked(folder, *args):
    # core.hooksPath is passed with -c for ONE command. The fixture's own
    # environment (see _hermetic) keeps the machine's and the user's git
    # configuration out of it entirely: nothing is read, nothing is written.
    # `folder` is the hooks folder the checked repository really
    # uses (this piece's folder when nothing is installed), so the test proves
    # the hooks git would run, including per-repository copies.
    return ["git", "-c", "core.hooksPath=" + folder] + list(args)


KEY_FILE = ".fixture-vault.env"


def _plant_config(repo):
    """Gives the throwaway repository a doorman.toml and a key file.

    Without a doorman.toml the guard is not configured for the repository: it
    lets everything through and says so, so a fixture without one can never
    prove it stops anything. The fake key is planted as the VALUE of a key
    registered in this fixture, because that is what the guard detects. The key
    file and the guard's own scratch files are excluded from git, so the test
    commits never stage the vault.
    """
    io.open(os.path.join(repo, KEY_FILE), "w", encoding="utf-8", newline="\n").write(
        "FIXTURE_KEY=%s\n" % FAKE_KEY)
    io.open(os.path.join(repo, "doorman.toml"), "w", encoding="utf-8", newline="\n").write(
        'key_files = ["%s"]\n' % KEY_FILE)
    ex = os.path.join(repo, ".git", "info", "exclude")
    os.makedirs(os.path.dirname(ex), exist_ok=True)
    io.open(ex, "a", encoding="utf-8", newline="\n").write(
        "%s\n.doorman-known\n.doorman-lastrun\n" % KEY_FILE)


def _check_pre_commit(tmp, folder):
    """Proves `pre-commit`, through the real hook folder.

    A missing, non-executable or broken `pre-commit` must not sit next to the
    words "the door is healthy", so `pre-commit` gets its own proof, with this
    folder's hooks applied to the COMMIT itself:
      1. a commit of a clean file must SUCCEED (if not, the harness or the hook
         is broken and nothing after it means anything);
      2. a commit of a file carrying the fake key must FAIL, print the
         reviewer's own words, and not print the key.
    """
    env = _hermetic(tmp)
    repo = os.path.join(tmp, "commit_repo")
    _must(["git", "init", "-q", repo], env=env)
    _must(["git", "config", "user.email", "watch@local"], cwd=repo, env=env)
    _must(["git", "config", "user.name", "watch"], cwd=repo, env=env)
    _plant_config(repo)

    io.open(os.path.join(repo, "ok.txt"), "w", encoding="utf-8").write("clean\n")
    _must(["git", "add", "-A"], cwd=repo, env=env)       # `add` runs no hook
    control = _sh(_hooked(folder, "commit", "-qm", "clean"), cwd=repo, env=env)
    if control.returncode != 0:
        out = ((control.stdout or "") + (control.stderr or "")).strip().splitlines()
        return False, ("inconclusive: a CLEAN commit was rejected too%s"
                       % ((" - " + out[-1][:80]) if out else ""))

    io.open(os.path.join(repo, "x.py"), "w", encoding="utf-8").write(
        'K = "%s"\n' % FAKE_KEY)
    _must(["git", "add", "-A"], cwd=repo, env=env)
    r = _sh(_hooked(folder, "commit", "-qm", "with a key"), cwd=repo, env=env)
    output = (r.stdout or "") + (r.stderr or "")
    if r.returncode == 0:
        return False, "the fake key WENT THROUGH the commit: pre-commit is not stopping"
    if FAKE_KEY in output:
        return False, "pre-commit stopped it, but PRINTED the key value"
    if PROOF not in output:
        return False, ("inconclusive: the commit was rejected, but not by the "
                       "reviewer")
    return True, "the clean commit went through, the fake key commit was stopped by the reviewer, and its value was not printed"


def _check_pre_push(tmp, folder):
    """Proves `pre-push`, through the real hook folder, on a real push."""
    env = _hermetic(tmp)
    bare = os.path.join(tmp, "remote.git")
    work = os.path.join(tmp, "work")
    # The FIXTURE commits below are built with an empty hooks
    # folder ON PURPOSE. A push can only carry a key that is already committed,
    # so the commit must exist without `pre-commit` stopping it first.
    # `pre-commit` is proven separately, above, with
    # the real folder. A global core.hooksPath on this machine would otherwise
    # also run its own hooks on the fixture.
    nohooks = os.path.join(tmp, "nohooks")
    os.makedirs(nohooks)
    g = ["git", "-c", "core.hooksPath=" + nohooks]
    _must(["git", "init", "-q", "--bare", bare], env=env)
    _must(["git", "init", "-q", work], env=env)
    _must(g + ["config", "user.email", "watch@local"], cwd=work, env=env)
    _must(g + ["config", "user.name", "watch"], cwd=work, env=env)
    _must(g + ["remote", "add", "origin", bare], cwd=work, env=env)
    _plant_config(work)

    io.open(os.path.join(work, "ok.txt"), "w", encoding="utf-8").write("clean\n")
    _must(g + ["add", "-A"], cwd=work, env=env)
    _must(g + ["commit", "-qm", "clean"], cwd=work, env=env)
    control = _sh(_hooked(folder, "push", "origin", "HEAD:main"), cwd=work, env=env)
    if control.returncode != 0:
        out = ((control.stdout or "") + (control.stderr or "")).strip().splitlines()
        return False, ("inconclusive: a CLEAN push was rejected too%s"
                       % ((" - " + out[-1][:80]) if out else ""))

    io.open(os.path.join(work, "x.py"), "w", encoding="utf-8").write(
        'K = "%s"\n' % FAKE_KEY)
    _must(g + ["add", "-A"], cwd=work, env=env)
    _must(g + ["commit", "-qm", "with a key"], cwd=work, env=env)
    r = _sh(_hooked(folder, "push", "origin", "HEAD:main"), cwd=work, env=env)
    output = (r.stdout or "") + (r.stderr or "")
    if r.returncode == 0:
        return False, "the fake key WENT THROUGH the push: pre-push is not stopping"
    if FAKE_KEY in output:
        return False, "pre-push stopped it, but PRINTED the key value"
    if PROOF not in output:
        return False, ("inconclusive: the push was rejected, but not by the "
                       "reviewer")
    return True, "the clean push went through, the fake key push was stopped by the reviewer, and its value was not printed"


def _in_throwaway(prefix, check, folder):
    """Runs one check in its own temporary folder, always cleaned up."""
    tmp = tempfile.mkdtemp(prefix=prefix)
    try:
        return check(tmp, folder)
    except SetupFailed as e:
        return False, "inconclusive: the fixture failed - %s" % e
    except Exception as e:
        return False, "the test could not run (%s: %s)" % (type(e).__name__, e)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def run_hook_tests(prefix, folder):
    """BOTH hooks, each proven on its own and reported on its own.

    A failure of one never hides the other: both always run. Returns
    [(hook, ok, reason), ...]. Callers must treat anything but ok=True as
    "not proven", including "could not run".
    """
    return [("pre-commit",) + _in_throwaway(prefix, _check_pre_commit, folder),
            ("pre-push",) + _in_throwaway(prefix, _check_pre_push, folder)]


def main():
    ap = argparse.ArgumentParser(prog="door_watch.py", description=
                                 "Checks that Doorman Jay is still standing.")
    ap.add_argument("--brief", action="store_true",
                    help="one line only, for a startup check")
    # The watchman can be pointed at any repository.
    ap.add_argument("--repo", metavar="PATH",
                    help="the repository to check (default: the current folder)")
    args = ap.parse_args()
    brief = args.brief
    repo = os.path.abspath(args.repo) if args.repo else os.getcwd()

    route, folder, detail = detect_route(repo)

    # Outside a git repository the question has no answer. Say so
    # plainly and exit non-zero; do not guess and do not run the tests.
    if route is None:
        if brief:
            print("\n\U0001F511 Doorman Jay cannot be checked: %s.\n" % detail)
        else:
            print()
            print("  installed              : cannot tell - %s" % detail)
            print()
            print("  the door could NOT be checked. Run this inside a git repository,")
            print("  or point it at one with --repo <path>.")
            print()
        return 1

    installed = route in (ROUTE_REPO, ROUTE_MACHINE)
    missing = files_in_place(route, folder)
    # The tests use the hooks folder this repository really uses;
    # with nothing installed they use this piece's own folder.
    test_folder = folder if installed else HERE
    # BOTH hooks are proven, separately. "Healthy" needs both.
    results = run_hook_tests("door_watch_", test_folder)
    failed = [h for h, ok, _ in results if not ok]
    stops = not failed
    reason = "; ".join("%s: %s" % (h, r) for h, ok, r in results if not ok)

    healthy = installed and not missing and stops

    if brief:
        if healthy:
            return 0        # all well: a startup check says nothing
        if not installed:
            print("\n\U0001F511 Doorman Jay is waiting for your yes to be switched on "
                  "(%s). Fake key test: %s.\n"
                  % (detail, "passes" if stops else reason))
        else:
            print("\n\U0001F511 Doorman Jay needs a look: %s\n"
                  % ("; ".join(missing) if missing else reason))
        return 1

    print()
    print("  repository             : %s" % repo.replace("\\", "/"))
    print("  installed              : %s - %s" % (route, detail))
    print("  files in place         : %s" % ("yes" if not missing else "; ".join(missing)))
    for hook, ok, why in results:
        print("  %s : %s %s"
              % (("%s key test" % hook).ljust(22),
                 "PROVEN -" if ok else "NOT PROVEN -", why))
    print()
    print("  %s" % ("the door is healthy." if healthy else "the door is NOT closing yet."))
    if failed:
        print("  Not proven: %s." % ", ".join(failed))
    if not installed:
        print()
        print("  To switch it on for this repository (recommended; touches no git config):")
        print('     python "%s" --repo "%s"'
              % (os.path.join(HERE, "install.py").replace("\\", "/"),
                 repo.replace("\\", "/")))
    print()
    return 0 if healthy else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print("\n🔑 the door watchman crashed (%s: %s) and needs a look by "
              "hand.\n" % (type(e).__name__, e))
        sys.exit(1)
