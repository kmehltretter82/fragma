# fragma run

Revision: `b9b3e33b70b71e516930117e21de3ad2a7723747`

Result: **incomplete**

| Target | Profile | Result |
| --- | --- | --- |
| string.strnchr | x86_64-gcc | unsupported |
| string.strlcat | x86_64-gcc | inconsistent |
| calibration.strlcat.naive.wp | x86_64-gcc | inconsistent |
| calibration.strlcat.naive.eva | x86_64-gcc | incomplete |
| calibration.s390.byte-order.eva | s390x-gcc | incomplete |
| calibration.string.truncation.eva | x86_64-gcc | calibration-passed |
| calibration.string.no_copy_room.eva | x86_64-gcc | calibration-passed |
| calibration.string.full_copy.eva | x86_64-gcc | calibration-passed |
| calibration.string.first_match.eva | x86_64-gcc | calibration-passed |
| calibration.string.nul_conversion.eva | x86_64-gcc | calibration-passed |
| calibration.string.early_nul.eva | x86_64-gcc | calibration-passed |
| calibration.string.zero_count.eva | x86_64-gcc | calibration-passed |
| calibration.string.count_cutoff.eva | x86_64-gcc | calibration-passed |
| string.verified.strnchr | x86_64-gcc | passed |
| string.verified.strlcat | x86_64-gcc | passed |

See summary.json and each target's result.json for commands, assumptions,
source hashes, dependencies, warnings, and individual goal outcomes.
