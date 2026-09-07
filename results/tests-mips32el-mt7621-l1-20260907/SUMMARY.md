# MIPS32el MT7621 checkpoint regression

Result: **1,025 tests passed; 20 conditional skips; no failures or errors**.

The workspace regression command was:

```sh
python3 -m unittest discover -s tests -v
```

It completed in 25.945 seconds after the registered MT7621 profile, strict
MIPS Clang/Kbuild validation, pinned seed selection and CLI snapshot-name fix
were in place. This compact record reports the interactive run; the verbose
terminal stream is not committed as proof data.
