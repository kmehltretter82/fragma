# herdtools7 7.58 runtime library subset

This directory vendors the three generic CAT helper files needed to run the
Linux Kernel Memory Model with `herd7` 7.58. They are copied byte-for-byte from
the official herdtools7 tag `7.58`:

- repository: <https://github.com/herd/herdtools7>
- commit: `1ca343e16a2038e406d1ac674e7e3a1b722b36c7`
- tree: `271f7849890bbcc80d7f1b2106caa94cc18624ac`
- source paths: `herd/libdir/{stdlib.cat,cross.cat,cos-opt.cat}`

The pinned Linux snapshot supplies `linux-kernel.cat`, `lock.cat`, its Bell
parser configuration and its litmus tests. These vendored files do not replace
or modify the kernel's model. They only make the generic include resolution
explicit and reproducible because the Ubuntu `herdtools7` 7.58 package on the
development host reports the unusable compiled-in path
`/sbuild-nonexistent/share/herdtools7/herd`.

Expected SHA-256 identities:

| File | SHA-256 |
| --- | --- |
| `libdir/stdlib.cat` | `46c6eb7b5eb8820760d20b557280e9399ba247e30343ab8ad7e8cb72eee93624` |
| `libdir/cross.cat` | `8b2dbe9cc3175d5bd8067ab80b4c6024949c743d16e47b13f8230c52ca06bbde` |
| `libdir/cos-opt.cat` | `587b1a119119e8f6d4aec2fddf3df34245f09eb1cbcc374671f6951b1e604779` |
| `LICENSE.txt` | `5d8a5818161ab38b77226b7caa758fde63f1aaabdf87ea773e1620b62a5b9537` |

The upstream distribution applies the CeCILL-B license to these files. The
complete upstream license text is retained as [LICENSE.txt](LICENSE.txt).
Fragma invokes the installed executable with
`-set-libdir third_party/herdtools7-7.58/libdir`; it does not install or alter
system files.
