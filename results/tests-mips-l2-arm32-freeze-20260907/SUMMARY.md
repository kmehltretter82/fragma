# MIPS L2 and ARM32 campaign-freeze regression

Final result: **PASS**.

Command:

```sh
python3 -m unittest discover -s tests -q
```

The final post-replay run executed 1,043 tests in 25.629 seconds: all passed, with 20
conditional skips.

The immediately preceding full run is retained as a failed observation in this
record rather than omitted. It executed the same 1,043 tests and failed two:
the ARM64 CPUID and RISC-V encoder unit tests still required the old
`docs/pointer-policy-review.md` input to match the current file. Commit
`c9cf0ca` had deliberately changed that document to call its ten-profile
review dated after MIPS registration. The target review contexts correctly
retain old SHA-256
`bf605644084d3d9c83563d21231a75107c3110c85933d6def5b3106cec1adca9`,
while the current document is
`2ac8c3b45f489b4fc696385daca320913953befc8f35df1d0b10fc2a54d05799`.

The test correction now requires that exact known mismatch and requires every
other target-bound file to retain its recorded identity. No old review hash was
refreshed, no proof was relabeled current, and no analyzer result changed.
