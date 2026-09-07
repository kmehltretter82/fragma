# fragma run

Revision: `b9b3e33b70b71e516930117e21de3ad2a7723747`

Result: **incomplete**

| Target | Profile | Result |
| --- | --- | --- |
| string.strnchr | x86_64-gcc | unsupported |
| string.strlcat | x86_64-gcc | inconsistent |
| calibration.strlcat.naive.wp | x86_64-gcc | inconsistent |
| calibration.strlcat.naive.eva | x86_64-gcc | incomplete |
| mpi.rshift | x86_64-gcc | unsupported |
| arm64.immediates | arm64-gcc | inconsistent |
| arm64.cpuid | arm64-gcc | passed |
| riscv.base-encoders | riscv64-gcc | passed |
| calibration.string.truncation.eva | x86_64-gcc | tool-error |
| calibration.string.no_copy_room.eva | x86_64-gcc | tool-error |
| calibration.string.full_copy.eva | x86_64-gcc | tool-error |
| calibration.string.first_match.eva | x86_64-gcc | tool-error |
| calibration.string.nul_conversion.eva | x86_64-gcc | tool-error |
| calibration.string.early_nul.eva | x86_64-gcc | tool-error |
| calibration.string.zero_count.eva | x86_64-gcc | tool-error |
| calibration.string.count_cutoff.eva | x86_64-gcc | tool-error |
| string.verified.strnchr | x86_64-gcc | passed |
| string.verified.strlcat | x86_64-gcc | passed |

See summary.json and each target's result.json for commands, assumptions,
source hashes, dependencies, warnings, and individual goal outcomes.
