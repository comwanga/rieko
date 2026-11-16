# Rieko Claude Code skills

Project skills for working on Rieko with Claude Code. Each directory holds one skill;
Claude loads a skill's `SKILL.md` when its description matches the task, or when you
type `/<skill-name>`.

## Written for this repository

| Skill | Use it for |
|---|---|
| `rieko-async-reliability` | The agent runtime: poll loops, `select!`, blocking storage, timeouts, shutdown, webhook handoff |
| `rieko-finding-integrity` | Detectors, finding lifecycle and resolution, evidence, explanations, recommendations |
| `rieko-security-boundaries` | The read-only guarantee, auth, binding, webhook HMAC, secrets, headers, outbound data |
| `rieko-operator-ui` | Everything under `frontend/`, including any future chart |
| `rieko-surface-parity` | Keeping the API, UI types, CLI, docs and tests in step |
| `rieko-verification` | Which checks to run for a change and how to report the result |

These describe patterns in the code. When the code changes a pattern, change the skill
in the same pull request.

## Third-party

| Skill | Source | Commit | Licence |
|---|---|---|---|
| `svelte-core-bestpractices` | https://github.com/sveltejs/ai-tools (`plugins/claude/svelte/skills/svelte-core-bestpractices`) | `d3e755be770277d8c75fe61109b103b801b12775` | MIT, see `svelte-core-bestpractices/LICENSE` |
| `accessibility` | https://github.com/addyosmani/web-quality-skills (`skills/accessibility`) | `afa8da942115f2961fdbfa80807ea0b232ff6c00` | MIT, see `accessibility/LICENSE` |

Both contain Markdown only: no scripts, hooks or network configuration. `LICENSE` in
each directory is the upstream repository's licence file, which the MIT licence requires
to accompany copies.

`svelte-core-bestpractices` is byte-identical to upstream. `accessibility` differs by one
line: the link to `../web-quality-audit/SKILL.md` was removed from its References list
because that sibling skill is not installed here.

`CHECKSUMS.sha256` records the files as committed; verify with
`sha256sum -c CHECKSUMS.sha256` from this directory. `.gitattributes` disables line-ending
conversion here so the checksums hold on every platform. To update a skill, review the
upstream diff, copy the new files, reapply the change above if it still applies, and
update the commit and checksums.

Where a third-party skill and a Rieko skill disagree, the Rieko skill applies. Two known
cases: `svelte-core-bestpractices` recommends replacing legacy Svelte syntax, which here
is done only when a task asks for it; `accessibility` mentions installing audit tools
globally, which here needs approval first.
