#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
install.py - prepares Doorman Jay. It never edits your git configuration:
it writes files and PRINTS the commands you may run yourself.

    python install.py                    per repository (recommended): this folder's repo
    python install.py --repo <path>      per repository: that repo
    python install.py --template [dir]   for repositories created or cloned from now on
    python install.py --machine-wide     prints the machine-wide switch, with its warning
    python install.py --test             also sends a fake key through the door (any mode)

PER REPOSITORY (the default, and the recommended one). Copies the two hooks into
the repository's own hooks folder, as `git rev-parse --git-path hooks` reports
it. It needs no `git config` at all: nothing global is touched, other
repositories and other hooks are not affected. If a hook of the same name is
already there and this piece did not write it, the installer stops and does not
overwrite it. Recommended because it takes nothing away from anyone.

TEMPLATE. Writes the hooks into git's template folder and prints the one
`git config --global init.templateDir` line for you to run. It only affects
repositories created or cloned AFTER that; existing ones are left alone. It is
additive: nothing that already works stops working.

MACHINE-WIDE. Prints the `core.hooksPath` line for you to run. That makes git
use ONE folder for EVERY hook of EVERY repository: other hooks (commit-msg,
post-checkout, the ones inside repositories) stop running and a previous value
is replaced. It is available because some owners want exactly that, and it is
never the default.
"""
import io
import os
import sys
import argparse
import stat
import shutil
import tempfile
import subprocess

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATES = os.path.join(HERE, "templates")
FAKE_KEY = "AIza" + "SyD-test" + "0123456789abcdefghijklmnop"


def interpreter():
    """The ABSOLUTE path of this Python.

    Absolute on purpose: the hook can start from an editor, from an agent or
    from a terminal, and each brings its own PATH. "python" could be another
    version, a Windows Store alias, or nothing at all.
    """
    return sys.executable.replace("\\", "/")


# Every hook this piece writes carries this marker. It is how a
# later run tells "mine, safe to replace" from "somebody else's, hands off".
MARKER = "doorman-jay-hook:v1"
MARKER_LINE = ("# %s - written by 05-doorman-jay/install.py. Re-running the "
               "installer replaces this file." % MARKER)

HOOKS = ("pre-push", "pre-commit")

# The line in both templates that chains to a repository's own hook of the same
# name. In a per-repo or template copy the hook IS that file, so chaining would
# call itself forever.
_CHAIN = 'if [ -x "$LOCAL" ] && [ "$LOCAL" != "$ME" ]; then'
_WHOLE_MACHINE = ('# Switch it on for the whole machine with:\n'
                  '#     git config --global core.hooksPath "@FOLDER@"')


def render_hook(name, own_folder):
    """The text of one hook, with the paths of this machine.

    own_folder=True: the file stays in this folder (machine-wide, and --test).
    own_folder=False: the file is copied into a repository's hooks folder or
    into git's template folder.
    """
    template = os.path.join(TEMPLATES, name + ".sh")
    text = io.open(template, encoding="utf-8", newline="").read().replace("\r\n", "\n")
    folder = HERE.replace("\\", "/")
    text = (text.replace("@PYTHON@", interpreter())
                .replace("@FOLDER@", folder)
                .replace("@NAME@", name))
    first, rest = text.split("\n", 1)
    # Marker right under the shebang, so the installer can
    # recognise its own hooks later.
    text = first + "\n" + MARKER_LINE + "\n" + rest
    if not own_folder:
        # The template chains to "$GITDIR/hooks/<name>", which for
        # a copy living in that very folder is the hook itself: it would call
        # itself without end. The chain is switched off in these copies.
        if _CHAIN not in text:
            raise RuntimeError("template %s.sh no longer has the chain line the "
                               "installer expects; refusing to write a hook that "
                               "could call itself" % name)
        text = text.replace(_CHAIN, 'if false; then  # per-repo copy: this file IS the hook')
        text = text.replace(_WHOLE_MACHINE.replace("@FOLDER@", folder),
                            "# This copy lives in a repository's (or git's template) hooks\n"
                            "# folder. Nothing global is switched on.")
    return text


def write_atomic(target, text):
    """Writes through a temporary file next to the target, then os.replace.

    newline="\n" ALWAYS: /bin/sh will not start a hook with CRLF line endings,
    and the failure is silent - git behaves as if the hook were not there.
    """
    folder = os.path.dirname(target)
    tmp = os.path.join(folder, ".%s.tmp%d" % (os.path.basename(target), os.getpid()))
    try:
        with io.open(tmp, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        os.chmod(tmp, os.stat(tmp).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        os.replace(tmp, target)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    raw = io.open(target, "rb").read()
    return len(raw), b"\r\n" not in raw


def write_hooks(folder=HERE):
    """Writes the two hooks into `folder` for machine-wide mode or a test."""
    done = []
    for name in HOOKS:
        size, lf = write_atomic(os.path.join(folder, name),
                                render_hook(name, own_folder=True))
        done.append((name, size, lf))
    return done


def is_ours(path):
    try:
        return MARKER in io.open(path, encoding="utf-8", errors="replace").read()
    except Exception:
        return False


def install_into(folder):
    """Copies both hooks into `folder`. Returns (foreign, written).

    A hook of the same name that this piece did not write is NEVER
    overwritten - that is the same sin as taking over a global hooks path. Both
    names are checked BEFORE anything is written, so a refusal leaves the folder
    exactly as it was.
    """
    foreign = [os.path.join(folder, n) for n in HOOKS
               if os.path.lexists(os.path.join(folder, n))
               and not is_ours(os.path.join(folder, n))]
    if foreign:
        return foreign, []
    os.makedirs(folder, exist_ok=True)
    written = []
    for name in HOOKS:
        size, lf = write_atomic(os.path.join(folder, name),
                                render_hook(name, own_folder=False))
        written.append((name, size, lf))
    return [], written


class SetupFailed(Exception):
    """A step of the fixture failed, so the test proves nothing."""


def _sh(args, cwd=None, env=None):
    return subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True,
                          timeout=180)


def _must(args, cwd=None, env=None):
    """Runs a setup step and INSISTS it worked.

    A failed setup step must never count as proof: a broken `git init`, a
    blocked commit or a bad remote would otherwise produce a reassuring "the
    fake key was stopped". A test that can pass for the wrong reason is worse
    than no test.
    """
    r = _sh(args, cwd=cwd, env=env)
    if r.returncode != 0:
        first = ((r.stderr or "") + (r.stdout or "")).strip().splitlines()
        raise SetupFailed("`%s` exited %d%s" % (" ".join(args[:2]), r.returncode,
                                                (": " + first[0][:90]) if first else ""))
    return r


# What the reviewer itself prints when it catches a key. The test demands this
# exact proof, not merely a non-zero exit: anything can fail a push.
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
    # configuration out of it entirely: nothing is read, nothing is written. `folder` is the
    # hooks folder under test: the source folder, or the repository's own.
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
    _must(["git", "config", "user.email", "test@local"], cwd=repo, env=env)
    _must(["git", "config", "user.name", "test"], cwd=repo, env=env)
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
    _must(g + ["config", "user.email", "test@local"], cwd=work, env=env)
    _must(g + ["config", "user.name", "test"], cwd=work, env=env)
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


def run_hook_tests(prefix, folder=None):
    """BOTH hooks, each proven on its own and reported on its own.

    A failure of one never hides the other: both always run. Returns
    [(hook, ok, reason), ...]. Callers must treat anything but ok=True as
    "not proven", including "could not run". `folder` is the hooks folder to
    prove: the one the user will actually run (the repository's own after a
    per-repository install), defaulting to this source folder.
    """
    if folder is None:
        folder = HERE
    return [("pre-commit",) + _in_throwaway(prefix, _check_pre_commit, folder),
            ("pre-push",) + _in_throwaway(prefix, _check_pre_push, folder)]


def _git_out(args, cwd=None):
    r = _sh(["git"] + args, cwd=cwd)
    return r.returncode, (r.stdout or "").strip()


def repo_hooks_dir(repo):
    """Asks git where THIS repository keeps its hooks.

    Never a guessed `.git/hooks`: worktrees and submodules keep them elsewhere.
    Returns (folder, error).
    """
    if not os.path.isdir(repo):
        return None, "%s is not a folder" % repo
    code, out = _git_out(["rev-parse", "--git-path", "hooks"], cwd=repo)
    if code != 0 or not out:
        return None, "%s is not inside a git repository" % repo
    # `--git-path hooks` obeys core.hooksPath. If one is set, the
    # answer is that shared folder, not this repository's own, and a hook
    # written there would be a machine-wide change by the back door.
    code, hp = _git_out(["config", "--get", "core.hooksPath"], cwd=repo)
    if hp:
        return None, ("core.hooksPath is set (%s), so this repository's own "
                      "hooks folder is not in use and git reads hooks from "
                      "there instead. Installing there would change every "
                      "repository that shares it, so nothing was written." % hp)
    return os.path.abspath(os.path.join(repo, out)), None


def template_dirs(arg):
    """(template_dir, hooks_dir) for --template. `arg` is the template folder."""
    if arg:
        base = os.path.abspath(arg)
    else:
        home = os.environ.get("XDG_CONFIG_HOME")
        if not home:
            home = ((os.environ.get("APPDATA") if sys.platform == "win32" else None)
                    or os.path.join(os.path.expanduser("~"), ".config"))
        base = os.path.join(home, "git-template")
    return base, os.path.join(base, "hooks")


def report_install(folder):
    foreign, written = install_into(folder)
    if foreign:
        print("  NOT INSTALLED. A hook that this piece did not write is already there:")
        for f in foreign:
            print("     %s" % f.replace("\\", "/"))
        print("  It was left untouched. Look at it, and decide what to do with it;")
        print("  the installer will not overwrite somebody else's hook.")
        print()
        return False
    for name, size, lf in written:
        print("  written  %-11s %5d bytes   LF endings: %s   -> %s"
              % (name, size, "yes" if lf else "NO - it will not start",
                 os.path.join(folder, name).replace("\\", "/")))
    return True


def install_repo(repo):
    """Per-repository install. Returns (exit_code or 0, the repo's hooks folder)."""
    print("  Mode: PER REPOSITORY (recommended)")
    folder, err = repo_hooks_dir(repo)
    if err:
        print("  NOT INSTALLED. %s" % err)
        print()
        return 2, None
    print("  Repository             : %s" % os.path.abspath(repo).replace("\\", "/"))
    print("  Its hooks folder       : %s" % folder.replace("\\", "/"))
    print()
    if not report_install(folder):
        return 3, None
    return 0, folder


def install_template(arg):
    """Template install. Returns (exit_code or 0, hooks folder, template base)."""
    base, hooks = template_dirs(arg)
    print("  Mode: TEMPLATE (repositories created or cloned from now on)")
    if not report_install(hooks):
        return 3, None, base
    return 0, hooks, base


def finish_template(base):
    """The closing words of --template, once the hooks are installed (and,
    with --test, proven)."""
    current = (_sh(["git", "config", "--global", "init.templateDir"]).stdout or "").strip()
    print()
    print("  Additive: it affects repositories created or cloned AFTER you switch")
    print("  it on, and takes nothing away from existing ones. Nothing global was")
    print("  touched by this installer.")
    if current and os.path.normcase(os.path.abspath(current)) != os.path.normcase(base):
        print("  Note: init.templateDir already points to %s;" % current)
        print("  the line below replaces it. Write it down first.")
    print()
    print("  To switch it on, when the owner of the machine decides to:")
    print()
    print('     git config --global init.templateDir "%s"' % base.replace("\\", "/"))
    print()
    return 0


def main():
    ap = argparse.ArgumentParser(
        prog="install.py", formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Prepares Doorman Jay. It writes files and prints commands; "
                    "it never edits your git configuration.",
        epilog="PER REPOSITORY (default, recommended): copies the two hooks into the\n"
               "repository's own hooks folder. No git config at all, nothing global is\n"
               "touched, it never overwrites a hook it did not write.\n\n"
               "TEMPLATE: writes the hooks into git's template folder and prints the one\n"
               "init.templateDir line for you to run. Affects repositories created or\n"
               "cloned afterwards; takes nothing away from existing ones.\n\n"
               "MACHINE-WIDE: prints the core.hooksPath line, with its warning. Git then\n"
               "uses ONE folder for EVERY hook, other hooks stop running and a previous\n"
               "value is replaced. An explicit choice, never the default.")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--repo", metavar="PATH",
                   help="install into that repository (default: the current folder's)")
    g.add_argument("--template", nargs="?", const="", metavar="DIR",
                   help="install into git's template folder (DIR/hooks); default "
                        "<config home>/git-template")
    g.add_argument("--machine-wide", action="store_true",
                   help="print the machine-wide core.hooksPath switch, with its warning")
    ap.add_argument("--test", action="store_true",
                    help="also send a fake key through the door")
    args = ap.parse_args()

    here = HERE.replace("\\", "/")
    print()
    print("  Python on this machine : %s" % interpreter())
    print("  Door folder            : %s" % here)
    print()

    # Machine-wide points at hooks in THIS folder; per-repo and template
    # installs do not need them. A plain test instead uses a temporary folder.
    # With --test --repo, the installed copy is what gets proven, so the
    # install happens FIRST and nothing is written into this source folder.
    # The same holds for --template: whichever destination is being installed
    # is installed FIRST and THAT copy is what gets proven. Only plain --test
    # and --machine-wide prove this source folder, because there it IS what runs.
    repo_first = args.test and args.repo is not None
    template_first = args.test and args.template is not None
    installed_first = repo_first or template_first
    test_folder = None
    template_base = None
    plain_test = (args.test and args.repo is None and args.template is None
                  and not args.machine_wide)
    temporary_hooks = None
    try:
        if plain_test:
            temporary_hooks = tempfile.mkdtemp(prefix="doorman_jay_hooks_")
            test_folder = temporary_hooks
        if (args.test or args.machine_wide) and not installed_first:
            for name, size, lf in write_hooks(test_folder or HERE):
                print("  written  %-11s %5d bytes   LF endings: %s"
                      % (name, size, "yes" if lf else "NO - it will not start"))

        if repo_first:
            code, test_folder = install_repo(args.repo)
            if code:
                return code
        elif template_first:
            code, test_folder, template_base = install_template(args.template)
            if code:
                return code

        if args.test:
            print()
            # One line per hook, each with its own verdict. The door
            # is ready only when BOTH were proven.
            results = run_hook_tests("doorman_jay_", test_folder)
            for hook, ok, reason in results:
                print("  %s : %s %s"
                      % (("%s key test" % hook).ljust(22),
                         "PROVEN -" if ok else "NOT PROVEN -", reason))
            if not all(ok for _, ok, _ in results):
                print()
                print("  The door is NOT ready. Look at the lines above before going on.")
                return 1

        if template_first:
            return finish_template(template_base)

        if repo_first:
            print()
            print("  Done. This needed no `git config` at all: nothing global was touched,")
            print("  and no other repository or hook was affected.")
            print()
            return 0

        if plain_test:
            # `--test` on its own stays a pure proof: it
            # does not also install into whatever repository you happen to be in.
            print()
            print("  Tested only. To install, name a mode: --repo <path> (recommended),")
            print("  --template, or --machine-wide.")
            print()
            return 0

        if args.machine_wide:
            # An explicit choice, with the cost
            # said first. core.hooksPath makes git look for EVERY hook in one folder.
            current = (_sh(["git", "config", "--global", "core.hooksPath"]).stdout or "").strip()
            print()
            print("  WARNING - machine-wide means this:")
            print("   - git will use this ONE folder for EVERY hook of EVERY repository.")
            print("   - Other hooks (commit-msg, post-checkout, the ones inside your")
            print("     repositories) STOP RUNNING, because they are not in this folder.")
            print("   - A previous core.hooksPath is REPLACED.")
            print("   - The way back is to restore the value you had saved, NOT --unset")
            print("     (--unset leaves you with no hooks folder at all).")
            print()
            if os.path.normcase(os.path.abspath(current or "x")) == os.path.normcase(HERE):
                print("  Current global value   : %s   (already this folder)" % current)
            elif current:
                print("  Current global value   : %s" % current)
                print("  WRITE IT DOWN before you switch: that is what you restore.")
            else:
                print("  Current global value   : (none)")
                print("  Nothing to restore: going back means --unset.")
            print()
            print("  To switch it on, when the owner of the machine decides to:")
            print()
            print('     git config --global core.hooksPath "%s"' % here)
            print()
            print("  For one test run, without switching anything on:")
            print()
            print('     git -c core.hooksPath="%s" push' % here)
            print()
            return 0

        if args.template is not None:
            code, _hooks, base = install_template(args.template)
            if code:
                return code
            return finish_template(base)

        code, _ = install_repo(args.repo if args.repo else os.getcwd())
        if code:
            return code
        print()
        print("  Done. This needed no `git config` at all: nothing global was touched,")
        print("  and no other repository or hook was affected.")
        print()
        return 0
    finally:
        if temporary_hooks is not None:
            shutil.rmtree(temporary_hooks, ignore_errors=True)

if __name__ == "__main__":
    sys.exit(main())
