// SPDX-License-Identifier: BlueOak-1.0.0
/*
 * Minimal known-answer test for FairPlayBridge.kt.
 *
 * Build and run:
 *     kotlinc FairPlayBridge.kt FairPlayBridgeTest.kt -include-runtime -d test.jar
 *     java -jar test.jar        # prints PASS/FAIL, exit status 1 on mismatch
 *
 * Vector generated from the reference implementation; the Go, Rust, C, Python
 * and C# ports assert the same numbers, so all of them agree bit-for-bit.
 */

/**
 * Ground-truth vectors, captured from Apple's own code.
 *
 * The KAT above was generated from this project's own reference implementation,
 * so it proves the ports agree with each other -- not that any of them is right.
 * An earlier version shipped a bespoke 64-entry constant table that passed every
 * self-generated KAT and was still wrong: the single block those KATs exercised
 * has a payload-independent message and never triggers the round-31 permutation.
 *
 * Each vector below is a (state, message, result) triple lifted from a trace of
 * Apple's real bridge hash, together spanning all three per-hash offsets, both
 * mutation variants, and three blocks whose message genuinely varies with the
 * payload.
 */
private class HwKat(
    val name: String,
    val offset: Int,
    val variant: FairPlayBridge.BridgeMutation,
    val state: IntArray,
    val msg: IntArray,
    val want: IntArray,
)

private fun hardwareKats(): List<HwKat> = listOf(
    HwKat("B1", FairPlayBridge.BRIDGE_HASH1_OFFSET, FairPlayBridge.BridgeMutation.KDF,
        intArrayOf(0xb9f3dcdc.toInt(), 0xfbdc740b.toInt(), 0x60f77f86, 0x51907216),
        intArrayOf(0x4739a369, 0x98051ca8.toInt(), 0xcc907eb5.toInt(), 0x2b2f24b1,
            0x6a9cf800, 0x307a5e9e, 0xe083f082.toInt(), 0x05f89a33,
            0xb5827de2.toInt(), 0xac11f834.toInt(), 0x4bb8d831, 0x907269ea.toInt(),
            0x47a571ef, 0xbaa9597f.toInt(), 0x10651a4b, 0x9759f089.toInt()),
        intArrayOf(0xf20bb0af.toInt(), 0x2d1ce261, 0xe8e91068.toInt(), 0xec7e94db.toInt())),
    HwKat("B3", FairPlayBridge.BRIDGE_HASH1_OFFSET, FairPlayBridge.BridgeMutation.KDF,
        intArrayOf(0xae98150b.toInt(), 0xcab5b264.toInt(), 0x5800b818, 0xcd8094af.toInt()),
        intArrayOf(0xec44bb2f.toInt(), 0x6d4b9c49, 0x75e66e88, 0xd4012450.toInt(),
            0x0758a421, 0x019ee7e0, 0xd437cbea.toInt(), 0x7d8def76,
            0xc91e3235.toInt(), 0xe57a6ce0.toInt(), 0x43b44a7e, 0x6e1ce5ed,
            0x42ed3697, 0x84f0cfd9.toInt(), 0x34c43487, 0xe05a1a5a.toInt()),
        intArrayOf(0xa5cdff64.toInt(), 0xef81680a.toInt(), 0x9ea37b66.toInt(), 0x3f794376)),
    HwKat("B5", FairPlayBridge.BRIDGE_HASH1_FINAL_OFFSET, FairPlayBridge.BridgeMutation.KDF,
        intArrayOf(0xcce8dabc.toInt(), 0xdf507ee8.toInt(), 0x5cea1ef2, 0xe7174fa7.toInt()),
        intArrayOf(0xc629579b.toInt(), 0xd9b6360a.toInt(), 0xc8701f59.toInt(), 0xfbe19fe3.toInt(),
            0x4fec4e27, 0x5efdf2e8, 0x3097ae70, 0xfbe0003f.toInt(),
            0x1c398000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000000, 0x10090000, 0x00000000),
        intArrayOf(0x367c7f22, 0x37dde99e, 0xc0c00053.toInt(), 0x1247390a)),
    HwKat("C1", FairPlayBridge.BRIDGE_HASH2_OFFSET, FairPlayBridge.BridgeMutation.CYCLE,
        intArrayOf(0xd39b6229.toInt(), 0x9ae94dd0.toInt(), 0x8c31d460.toInt(), 0xeb9bd436.toInt()),
        intArrayOf(0xc9bc378d.toInt(), 0x335c58bf, 0x983d6c0c.toInt(), 0x5f154286,
            0xa3779d24.toInt(), 0x0d5503c2, 0xbd5e95a6.toInt(), 0xe2d33f57.toInt(),
            0x925d2306.toInt(), 0x88ec9d58.toInt(), 0x28937d55, 0x6d4d0f0e,
            0x24801713, 0x9783fea3.toInt(), 0xed3fbf6f.toInt(), 0x743495ad),
        intArrayOf(0xc6bf6e93.toInt(), 0x542728dc, 0xe90f673c.toInt(), 0x5ae9bfa5)),
    HwKat("C2", FairPlayBridge.BRIDGE_HASH2_OFFSET, FairPlayBridge.BridgeMutation.CYCLE,
        intArrayOf(0xd1dd1548.toInt(), 0xefd049ca.toInt(), 0x68e33ee6, 0x3d31dc46),
        intArrayOf(0x8f831b50.toInt(), 0x5b78ef45, 0x14c24b8d, 0x03f28b33,
            0xb972d234.toInt(), 0xf91c2a4b.toInt(), 0x870a4976.toInt(), 0x68e04f99,
            0x4f338181, 0x642e5904, 0xc006efcd.toInt(), 0x4b5e1860,
            0x1b08c6a8, 0x4a5cda50, 0x3d457ddd, 0x20aca5db),
        intArrayOf(0xd30fe3ad.toInt(), 0x8670fb82.toInt(), 0xc1ebdda2.toInt(), 0x3fb07aa8)),
)

private fun hex(a: IntArray) = a.joinToString { it.toUInt().toString(16) }

private fun runHardwareKats(): Int {
    var failures = 0
    for (k in hardwareKats()) {
        val state = k.state.copyOf()
        FairPlayBridge.compress(state, k.msg.copyOf(), k.offset, k.variant)
        if (!state.contentEquals(k.want)) {
            System.err.println("FAIL: hardware KAT ${k.name} — got ${hex(state)}, want ${hex(k.want)}")
            failures++
        }

        // Control: the offset and the round-31 permutation must both matter.
        val s2 = k.state.copyOf()
        FairPlayBridge.compress(s2, k.msg.copyOf(), k.offset + 1, k.variant)
        if (s2.contentEquals(k.want)) {
            System.err.println("FAIL: ${k.name}: offset is not load-bearing")
            failures++
        }

        val flipped = if (k.variant == FairPlayBridge.BridgeMutation.KDF)
            FairPlayBridge.BridgeMutation.CYCLE else FairPlayBridge.BridgeMutation.KDF
        val s3 = k.state.copyOf()
        FairPlayBridge.compress(s3, k.msg.copyOf(), k.offset, flipped)
        if (s3.contentEquals(k.want)) {
            System.err.println("FAIL: ${k.name}: mutation variant is not load-bearing")
            failures++
        }
    }
    return failures
}

fun main() {
    val message = intArrayOf(
        2546976663.toInt(), 960577546, 1698508769.toInt(), 1855391692.toInt(),
        3391201467.toInt(), 2557583070.toInt(), 3274602661.toInt(), 1912197568.toInt(),
        191961631, 1855758578.toInt(), 4196764585.toInt(), 2306695412.toInt(),
        2755794883.toInt(), 994892358, 790883565, 349006184,
    )
    val want = intArrayOf(0x3295ab96.toInt(), 0xea9e90eb.toInt(), 0x908160bd.toInt(), 0x2261d759)

    val state = FairPlayBridge.initialState()
    FairPlayBridge.compress(state, message, FairPlayBridge.BRIDGE_HASH1_OFFSET, FairPlayBridge.BridgeMutation.KDF)

    if (!state.contentEquals(want)) {
        System.err.println(
            "FAIL: bridge_md5_compress KAT — got ${state.joinToString { it.toUInt().toString(16) }}, " +
                "want ${want.joinToString { it.toUInt().toString(16) }}"
        )
        kotlin.system.exitProcess(1)
    }
    println("PASS: bridge_md5_compress KAT")

    val failures = runHardwareKats()
    if (failures != 0) {
        System.err.println("FAIL: bridge hardware KATs ($failures check(s) failed)")
        kotlin.system.exitProcess(1)
    }
    println("PASS: bridge hardware KATs (5 blocks, 3 offsets, 2 variants)")
}
