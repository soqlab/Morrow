"""Fuzzing for every parser that reads bytes a remote party controls.

checks.py holds one check per parser: it feeds the input to the parser and asserts the
properties that must hold for any input (only the documented error type escapes, the call
finishes within a time bound, nothing is allocated from an unchecked length field, and the output
stays consistent with the input). Two drivers run the same checks:

  * backend/test_fuzz_*.py -- Hypothesis, inside the normal pytest run. The example budget is
    small and the run derandomized by default, so a pull request sees a fixed, quick set; the
    nightly workflow raises MORROW_FUZZ_EXAMPLES and lets Hypothesis pick fresh inputs.
  * backend/fuzz/atheris_targets.py -- Atheris (libFuzzer), coverage-guided, byte level, for the
    nightly workflow (.github/workflows/fuzz.yml).

corpus/<target>/ holds the seed inputs (real handshakes and fixtures); corpus/<target>/regressions/
holds minimized inputs that once crashed or hung a parser. Every regression file is replayed by
test_fuzz_regressions.py on each run.
"""
