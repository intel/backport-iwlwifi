# Commit message format

This file defines the expected commit message format in this repository.
It is based on:

- Recent repository history, while excluding imported/merged kernel commits as examples.
- `intc-scripts/check-commit-msg.py` (enforced checks).
- `intc-scripts/commit-template` and developer docs.

## Required structure

```text
[OPTIONAL TAGS] <area>: <component>: <subject in imperative mood>

<body: explain why/how/side effects>

type=<bugfix|feature|cleanup|maint|maintenance>
ticket=<tracker>:<id> | ticket=none
[fixes=<Change-Id>|fixes=unknown]      # required when type=bugfix

Change-Id: I<40 hex chars> # generated automatically
Signed-off-by: <name> <email> # generated automatically when committing with -s
```

## Subject line rules

- Use imperative mood (`fix`, `add`, `remove`), not past tense.
- Most non-maint commits should start with `wifi:`.
- Typical prefix shape is `wifi: iwlwifi: ...` (or `wifi: mac80211: ...`, `wifi: cfg80211: ...`, etc.).
- Keep it short; around 65 chars is preferred (can exceed when needed).
- Do not end the subject with a period.

## Body rules

- Leave one blank line between subject and body.
- Body must not be empty.
- Keep lines below 75 characters.
- Cover:
  - why the change is needed,
  - the high-level approach,
  - side effects/behavior changes.

## Metadata and tags

- `type=` is required.
- `ticket=` is required.
  - Allowed trackers: `jira`.
  - `ticket=none` is allowed.
- For `type=bugfix`:
  - Subject must start with `[BUGFIX]`.
  - `fixes=` is required.
- If `[BUGFIX]` appears on non-bugfix commits, validation fails.
- `fixes=` can also be used for non-bugfixes, when we want a patch to be squashed into another one when sent upstream. When used for a bugfix, the fixes tag should contain the ChangeId of the commit that introduced the bug

## Optional leading subject tags

Seen in local history (non-kernel examples):

- `[BUGFIX]`
- `[NOUPSTREAM]` - use for patches that are not meant to be sent upstream
- Combined tags like `[BUGFIX][NOUPSTREAM]`

These tags are used before the normal subject prefix, for example:

```text
[BUGFIX] wifi: iwlwifi: mld: fix stale pointer
[NOUPSTREAM] wifi: iwlwifi: support new FSEQ version TLV
```

## Non-kernel examples from this repository log

Examples below were chosen from local/non-kernel-style commits (kernel merge/import messages were intentionally ignored):

- `chromeOS: apply any *.patch file per folder`
- `AI: Guide AI review to check spelling` # for such patches, the type must be maint
- `[NOUPSTREAM] ANDROID: build: update platform kernel manifest to support 6.18`
- `[BUGFIX] wifi: iwlwifi: mld: fix stale pointer`
- `wifi: iwlwifi: pcie: add debug print for resume flow if powered off`

## Practical template

```text
wifi: iwlwifi: <component>: <imperative summary>

<why this is needed>
<high-level approach>
<side effects / compatibility notes>

type=<feature|cleanup|maint|bugfix>
ticket=<tracker>:<id>
# fixes=I...            # required for bugfix, or when a patch needs to be squashed into another one when sent upstream

Change-Id: I........................................
Signed-off-by: Your Name <you@example.com>
```
