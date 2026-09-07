# Practical Linux MIPS target priorities

Updated: 2026-09-07. This is a maintenance and test-priority assessment, not a
sales-volume or installed-base census. Current OpenWrt release images and
upstream target maintenance are used as practical evidence that hardware remains
deployed and testable.

| Priority | Target family | Why it still matters | Fragma implication |
| --- | --- | --- | --- |
| 1 | MediaTek/Ralink MT7621 | A large deployed router/AP family with many current [OpenWrt 25.12.1 images](https://downloads.openwrt.org/releases/25.12.1/targets/ramips/mt7621/). | The first production MIPS profile: O32, little-endian MIPS32r2 SMP/CPS. L1 now passes. |
| 2 | Qualcomm Atheros ath79 | Older but still widely supported routers and access points; current release subtargets remain published under [ath79](https://downloads.openwrt.org/releases/25.12.1/targets/ath79/). | Add a separate big-endian MIPS32 profile and a representative real-board configuration. |
| 3 | Lantiq xRX200/xRX300 | DSL gateway hardware remains in the current [lantiq release target](https://downloads.openwrt.org/releases/25.12.1/targets/lantiq/). | Separate SoC, endian/configuration and device-I/O coverage from MT7621. |
| 4 | Realtek RTL838x/839x/930x/931x | Managed Ethernet switches remain an active [OpenWrt realtek target](https://github.com/openwrt/openwrt/tree/main/target/linux/realtek). | Valuable networking-driver and switch-SoC profile; do not infer it from generic MIPS32. |
| 5 | Broadcom BMIPS | Cable/DSL/set-top and router SoCs still receive current [bmips release images](https://downloads.openwrt.org/releases/25.12.1/targets/bmips/). | Add the exact BMIPS CPU/configuration variants independently. |
| 6 | Cavium OCTEON | 64-bit networking appliances remain covered by current [octeon release images](https://downloads.openwrt.org/releases/25.12.1/targets/octeon/). | First strong MIPS64 candidate; ABI, width and endian model must be new. |
| 7 | Ingenic XBurst | Linux-supported embedded/handheld SoCs remain relevant, though the deployment footprint is smaller than router targets. | Useful second little-endian MIPS32 family and runtime-board candidate. |

Malta is still valuable for QEMU and generic kernel calibration, but it is a
reference platform rather than the hardware priority. PIC32 devices remain
commercially available MIPS MCUs, but most are bare-metal/RTOS targets and are
not a first-order Linux-kernel verification target.

The order after MT7621 should favor what adds a genuinely new model dimension:
ath79 for big-endian MIPS32, then OCTEON for MIPS64, with Realtek/BMIPS/Lantiq
chosen when a reproducible kernel configuration and runtime target are
available. None inherits L1 or L2 from MT7621.
