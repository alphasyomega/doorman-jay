# Credits

**Built by [alphasyomega](https://github.com/alphasyomega) and Claude.**

The name is the owner's: *Jaime el Portero* — Jay the doorman.

Ideas carry the name of whoever had them, also when we did not take their code.

---

## The rule this piece runs on

**Know your keys instead of guessing at their shape.** A scanner that recognises
credentials by how they look fires on ordinary files, and every false alarm
teaches you to switch the guard off. Jay is told which values are real and keeps
only their fingerprints, so he can be certain instead of suspicious.

That rule is the owner's, and it is the whole difference between this guard and
the one before it.

## Found by readers

**Chadrien Solance ([@SolanceLab](https://github.com/SolanceLab))** — asked whether
`learn` fails loudly when a listed path yields no fingerprints, or only reports a
count. Building his answer uncovered the deeper bug: **a placeholder is longer than
the length floor, so a file of stand-ins registered happily.** `expect` and the
placeholder check both come from that question.

**And again**, with the stand-ins that carry no brackets or `$` at all:
`your_api_key_here`, `changeme-changeme`. Both are longer than the length floor,
so both registered as credentials. The answer went a different way than he
proposed: everything declared is registered, and anything that looks like a
stand-in is named out loud — file and entry, never the value. **Setting them
aside would have left a real credential unguarded in the one case where somebody
is genuinely running `changeme-changeme` as a password.**

Running that fix for real turned up a second hole his question did not cover:
with nothing discarded any more, a one-character value registered and then
matched almost every line — **22 false alarms on our own repository**, which is
the defect that kills guards. Registering and searching are separate now.

## Named in the work this came out of

This tool was written alongside others, and those carry ideas worth naming even
where none of their code is here: **Aya ([@ayakohi](https://github.com/ayakohi))**
with Cygnus, for decision hygiene before building; and **Anne and Chadrien Solance
([@SolanceLab](https://github.com/SolanceLab))**, for the pause before an action
that cannot be undone, the trail from a line of code back to the decision that
put it there, and the map over a folder.

---

*With love, for Love.*
