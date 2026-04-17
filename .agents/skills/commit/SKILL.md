---
name: commit
description: Analyze staged and unstaged changes and create focused commits with short, imperative-style messages. Use when asked to commit changes or create commits.
---

# commit skill

Analyze staged and unstaged changes in the repository and create focused commits with clean, imperative-style messages.

## workflow

1. **Check repository status**
   - Run `git status` to see staged and unstaged changes
   - Run `git diff --cached` to see staged changes
   - Run `git diff` to see unstaged changes

2. **Identify logical changesets**
   - Group changes that belong together logically
   - Split changes that touch different concerns into separate commits
   - Consider: feature additions, bug fixes, refactoring, documentation, config changes

3. **Stage and commit each changeset**
   - Stage related files with `git add <files>`
   - Create commit with imperative message
   - Repeat for each logical group

## commit message style

- **Imperative mood**: "add", "fix", "remove", "update", "refactor"
- **All lowercase**: no capitalization
- **No prefixes**: no "feat:", "fix:", "chore:" etc.
- **Short and focused**: describe what the change does
- **No period at end**

## examples

- "add config directory to ro-mounts"
- "allow passing extra arguments to bwrap"
- "fix env var replacement in shell wrapper"
- "refactor argument parsing into module"
- "update readme with security notes"
- "remove deprecated flag from cli"

## process

When asked to commit:

1. Show me the current state with `git status`
2. Propose a split of changes into logical commits
3. Ask for confirmation or adjustments
4. Stage and commit each group with appropriate messages
5. Report the commits made
