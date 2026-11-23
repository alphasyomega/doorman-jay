# Doorman Jay — the keeper of the keys

> **He knows your keys by their fingerprints, so he stops them leaving and never guesses.** *A guard that cries wolf is a guard you switch off.*

A pre-commit and pre-push guard that stops **your own** credentials from leaving
your machine.

It does not guess. It knows which keys belong to your repository because you
registered them: the guard reads your key files, stores a **sha256 fingerprint**
of each value, and reports a string only when its fingerprint is in that
registry. No provider format lists, no "this looks like a token", no heuristics
to tune.

One file. Python 3.11+. Standard library only. Windows and Linux.

---

## 🧭 Scope — read this before you install it

**Doorman Jay is built for a small private repository: your own projects, your
own machine, your own keys.**

It is a padlock that fits one door. It is designed against the failure that
actually happens to people working alone or in a tiny team — **you commit a key
by accident** — and nothing else.

**It is not** a secret-scanning product, a compliance control, or a defence
against someone who is deliberately attacking you. If an attacker already runs
code on your machine or can edit your hooks, this guard is not in their way. If
you need an audited scanner across many repositories and many contributors, use
a product built for that.

**It expects you to configure it for your own setup.** There is no sensible
default that fits every repository, and it does not try to invent one.

### Why it is configured per repository, and not once for your whole machine

Git can be told to use one hooks folder for every repository on a machine, and
the installer can do that (`--machine-wide`). **The guard itself still works
repository by repository, and that is not an oversight.**

A guard that knows its keys needs to be told, for each repository, **which files
hold the real credentials** and **which entries in them are not secrets**. Those
answers are different in every project: a web app keeps its keys in `.env`
beside a public URL, a script reads one key from a file outside the repository
altogether, a notes folder has no keys at all. There is no machine-wide answer,
so there is no machine-wide configuration.

The consequence, stated plainly: **a repository with no `doorman.toml` is not
guarded.** The hooks let the commit through and print that they checked nothing.
Installing the hooks once for the whole machine does **not** protect your
repositories — it only puts the guard in the doorway. Each repository still needs
its own `doorman.toml` and its own `learn`.

**If you want one command to see where you stand, run `door_watch.py --repo
<path>` per repository.** It reports whether the hooks are installed there and
whether a fake key is actually stopped — and it says so plainly when it cannot
tell.

---

## 🔎 Before you install: know where your keys actually are

**This guard can only protect keys it has been shown.** So the first step is not
installing it — it is knowing where your credentials actually are. Most people,
including the people who wrote this, did not.

### Your keys stay where they are

🔑 **Jay comes to your keys. You do not move your keys for Jay.**

If you keep a `.env` inside each project — which is what most people do — that is
fine. In that project's `doorman.toml` you point `key_files` at that project's own
`.env`. Fifty projects, fifty `.env` files, fifty configs, each naming its own.
**Nothing has to be gathered into one pile.**

If instead you keep your credentials in one place outside your repositories, point
`key_files` there. **Jay reads whatever paths you list.** It has no opinion.

### Why per repository, then?

**Because what differs between projects is not the keys. It is what to forgive.**

One project's `.env` holds a public support address and a site URL beside its real
secrets — those must never raise an alarm. Another project has no keys at all.
**A single machine-wide setting would have one answer for all of them**, and a guard
that cries wolf in one repository is a guard you switch off for every repository.

So: **the config is per repository. Where your keys live is up to you.**

### What a key file has to look like

Lines of `NAME=value`. That is all. A `.env`, or anything shaped like one.

🔴 **What Jay cannot read** — and will tell you so rather than reporting clean:

- **Placeholders instead of values.** A stand-in is longer than the 12-character
  floor, so a file of them used to register happily and guard nothing. **`learn`
  now sets them aside**: `${NAME}`, `$NAME`, `%NAME%`, `<your-key-here>`,
  `{{NAME}}`, `xxxxxxxx`, `........` and `--------` as whole values. *A real key
  that merely contains a brace is still a key.* If a file holds nothing else, it
  refuses to run.
- **A file that is PART placeholders.** Twelve stand-ins and two real keys reads as
  a healthy vault of two — which is correct, and is not what you meant if you were
  expecting fourteen. **Set `expect = 14` in the config and `learn` refuses when
  the count does not match**, naming both numbers, instead of printing a count
  nobody reads. *Suggested by Chadrien Solance.*
- **Values that live only in environment variables**, in no file at all. Write them
  into a key file Jay can read, or he cannot know them.
- **An inventory written in prose.** Useful to you, unreadable to a parser.

### Finding them in the first place

**Search by name, not by value.** Look for the files (`.env`, `*.env`,
`credentials.json`, `token.json`, `*.key`), then grep your configs for `API_KEY`,
`TOKEN`, `SECRET`, and list the environment variables whose names contain them.
**You do not need to read a single secret to build this list, and you should not
paste one into a terminal, a chat, or an agent's context.**

### Two habits of ours — offered, not required

**Neither of these is needed for Jay to work.** They are what we do, and why.

**Keeping the values outside every repository.** A credential inside a project
folder is one `rsync`, one backup, one copied folder away from leaving. Being
listed in `.gitignore` protects you from `git`, and from nothing else. *If you do
move them, make each program **stop and say so** when the file is missing — starting
up without its keys fails later, somewhere else, confusingly.*

**Keeping an inventory, and knowing it is not the source.** A list of which key is
which, when it was rotated, which are revoked — worth having. But a hand-written
label is not proof. **The live value is what the program reads. When they disagree,
the program wins.**

---

🔴 **Whatever you choose, point `key_files` at files that really hold values.**
A guard that knows nothing reports clean — **which is worse than no guard, because
now you trust it.**

## 📦 Install

1. Create `doorman.toml` at the root of the repository you want guarded:

   ```toml
   key_files    = [".env"]                         # this project's own key file...
   # key_files  = ["C:/secrets/keys.env"]          # ...or wherever yours live. Jay reads what you list.
   suspect      = false                             # optional; see "The switch"
   config_names = ["SUPPORT_EMAIL", "PUBLIC_SITE_URL"]  # optional; entries that are not secrets
   # expect     = 14                              # optional; learn refuses if the count does not match
   ```

2. Register your keys:

   ```
   python doorman_jay.py learn
   ```

   This writes `.doorman-known`: one line per key, `<fingerprint>  <NAME>`. It
   holds **fingerprints, never a credential**, and is safe to commit. It is
   re-learned on every run, so a rotated key needs no action.

3. Install the hooks:

   ```
   python install.py
   ```

---

## ⌨️ Commands

| | |
|---|---|
| `learn` | write the registry; print how many keys and their names |
| `check <path>...` | walk those paths and report matches |
| `pre-commit` | check the staged diff |
| `pre-push` | read push records on stdin; check each outgoing commit |
| `ack <path>...` | record that a person accepts these items as unread |
| `ack --all-unread` | accept everything the last `check` could not read |
| `--selftest` | build fixtures in a temp directory and prove the behaviour |

Every command takes `--repo <dir>`.

## 🚦 Exit codes

| | |
|---|---|
| `0` | nothing found, and everything was read |
| `1` | a registered key was found |
| `2` | the guard could not run, and it says why |
| `3` | nothing found, **but something could not be read** — not a clean result |

**Exit 3 exists on purpose.** A guard that prints "clean" after skipping a
symlinked folder or a file nobody could decode would tell you a drawer is safe
on the strength of files nobody looked at.

---

## 🙊 It never prints a credential

Not one character. A finding prints **where** it is, **which registered name**
it is, and **how many characters** long it is. Paths, branch names and reasons
pass through redaction before they are printed, so a file or branch named after
a key is not echoed either. A guard that prints the key puts the key in the log.

## ✅ "I know" — acknowledging what cannot be read

A PDF, a database or an image **can** hold a credential, so the guard never
calls them "nothing to read". It says they were not read, and that is exit 3.

You can accept an item once, on the record, with `ack`. `.doorman-unread` holds
one line per accepted item, bound to **both the path and the content**: if the
bytes at that path change later, the item is reported again and the output says
the content changed since it was acknowledged. The file holds hashes, never a
path, and may be committed.

Acknowledgements apply to `check` **only**. `pre-commit` and `pre-push` stay
strict: a binary being committed or pushed right now is an event, not scenery.

## 🔀 The switch

`suspect = false` is the default. Set it to `true` and a second pass also
reports anything that looks like a credential **by shape**, from a short list of
provider prefixes. **Turning it on means accepting false alarms**, because shape
is a guess and this tool otherwise refuses to guess.

---

## 📍 Limits and scope — what he catches, and what he does not

**A false alarm is a real defect in a guard** — it teaches its owner to switch
it off. So is a silent miss. Both are listed here.

### What it cannot see

- **A value that is not written plainly.** The guard matches the exact characters
  of a registered value. A key split across lines, assembled from pieces, written
  with escapes inside a single string, base64-encoded, URL-escaped or reversed is
  **not found**.

  **This is deliberate, and it is worth knowing why.** He is built to stop an
  *accident*: you or your agent pasting a key into a file and committing it without
  noticing. **An accident is always written plainly** — nobody base64-encodes their
  own key by mistake.

  A disguised key means somebody is smuggling it out on purpose, and **a git hook
  was never the defence against that**: the same person can email it, paste it in a
  chat, or photograph the screen.

  And the cost of trying would be the guard itself. To catch an encoded key he would
  have to **guess** — flagging every long random-looking string: hashes, ids, encoded
  blobs. **A guard that cries wolf is a guard you switch off — and a guard you
  switch off catches nothing at all.**

  **He stops accidents, not smuggling.**
- **Anything that is not UTF-8 text** — UTF-16 files, binaries, images — counts
  as NOT READ (exit 3), never as clean.
- **Merge commits.** `git show --unified=0` prints a combined diff, which holds
  only conflict resolutions. A key introduced by the merge itself is not seen.
- **A delete push** (local sha all zeros) sends no objects, so its ref names are
  not scanned. Deleting a badly named branch is the cure, not an event.
- **The `.git` folder** is not walked by `check`; it is recorded as NOT READ.

### Where it can cry wolf

- **A key file usually holds more than keys.** Your application reads that file
  at startup, so a public URL, a support address or a timezone may sit beside the
  credential — and `learn` would register them as keys, making ordinary files
  look like leaks. List those entries in `config_names` in `doorman.toml` and
  `learn` leaves them out, naming them every run (`excluded 4 config entry(s):
  ...`). A name that matches nothing in your key files is reported too, by name:
  a typo there would otherwise leave you believing you were protected from
  something that never happened.
- **An inline comment after a value** (`NAME=value # note`) becomes part of the
  value. Keep key-file lines to `NAME=value`.
- **Values under 12 characters are skipped** by `learn`. A short secret is not
  registered, and a 12-character threshold is a judgement, not a law.

### Without configuration

**With no `doorman.toml`, the hooks let the commit through and print that they
checked nothing.** That is deliberate: it is what allows installing the hooks
machine-wide. It is not failing silently — failing silently is claiming to guard
something you do not guard. `check` and `learn`, asked directly, exit 2 instead,
because whoever asks deserves an answer.

### Coverage we have not exercised

Stated so you can judge the guard, rather than trust it:

- `--machine-wide` and `--unset` are not covered by the self-test: they write
  into a live hooks directory.
- The pre-push path without configuration is proven through simulated input, not
  a real `git push`.
- A true Windows symlink (not a junction) needs a privilege the self-test does
  not request.
- Binding an acknowledgement to content reads the bytes of files the guard had
  declared too large to decode (over 64 MB). It streams them in 1 MB blocks
  without decoding, but a multi-gigabyte file is walked on every `check`.

---

## ⚠️ Warnings — read before you install him

> 🔴 **HE GUARDS ONE HOUSE: YOURS. TEACH HIM YOUR OWN KEYS.**
> He knows nothing out of the box. Until you register your keys, he lets everything through.

🔑 **He stores fingerprints, never the keys themselves.** A registered value is kept as a sha256 hash, so his own files cannot leak what he is guarding.

🚪 **Install him per repository, not once for your whole machine.** A global hooks path replaces whatever guard is already there, and between taking one out and putting the other in there is a moment with nobody watching.

🙈 **A false alarm teaches you to switch the guard off.** If he shouts about something that is not a secret — an address, a name that appears in your docs on purpose — pardon it in his config rather than ignoring him. A guard you ignore is not a guard.

---

## 🙏 Credit

**Built by [alphasyomega](https://github.com/alphasyomega) and Claude.**

The name is the owner's: *Jaime el Portero* — Jay the doorman.

The idea of a guard that knows its own keys rather than guessing at shapes came
out of watching shape-based scanners fire on ordinary files. The predecessor in
this family guessed; this one does not.

## ⚖️ Licence

See `LICENSE`.
