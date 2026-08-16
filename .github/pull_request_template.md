<!--
Thanks for contributing. Keep this short — the diff says what changed, so
use this space for what the diff cannot say.
-->

## What this changes

<!-- One or two sentences. -->

## What would break if you were wrong

<!--
This is the section reviewers actually read. Tell us the failure mode you
are guarding against, not a summary of the code. "If the dampener list is
evaluated after the amplifiers, a key in an auth test fixture gates the
build" is useful. "Refactored the path matching" is not.
-->

## Checklist

- [ ] `make check` passes (lint, the zero-dependency assertion, and tests)
- [ ] New behaviour has a test **named after the behaviour**, with a comment
      saying why the test exists
- [ ] No new third-party dependencies — or the case is argued in
      `ARCHITECTURE.md` and was agreed in an issue first
- [ ] Any new evidence reports an honest `Method`; heuristics are labelled
      as heuristics and never as proof
- [ ] Output is still deterministic — no map iteration, no wall-clock reads,
      no partial sort comparators
- [ ] If this touches path rules, there is a test for both a true positive
      and a plausible false positive
