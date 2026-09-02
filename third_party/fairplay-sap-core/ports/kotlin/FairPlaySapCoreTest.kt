/*
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * Conformance tests for FairPlaySapCore.kt.
 *
 *     kotlinc FairPlaySapCore.kt FairPlaySapCoreTest.kt -include-runtime -d t.jar
 *     java -jar t.jar ../../conformance
 *
 * Compile this WITHOUT FairPlayBridgeTest.kt -- both declare a top-level
 * main(), and the JVM will not take two.
 *
 * The expected values come from the CSV files in ../../conformance, generated
 * by the Go reference in fpsapcore. Computing them here would make
 * this a test that the code agrees with itself.
 */
import java.io.File
import kotlin.system.exitProcess

private var checks = 0
private var failures = 0

private fun check(ok: Boolean, what: String) {
    checks++
    if (!ok) { failures++; println("FAIL: $what") }
}

private fun hex(s: String) = ByteArray(s.length / 2) {
    ((Character.digit(s[it * 2], 16) shl 4) or Character.digit(s[it * 2 + 1], 16)).toByte()
}

private fun str(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

/** The unsigned-underflow trap. Kotlin's Int is signed, so this needs UInt. */
private fun testRingIndexUnderflowBoundary() {
    val x = FairPlaySapCore.buildRingIndices()[0]
    // 2^32 mod 210 == 46, and 55 + 46 == 101.
    check(x[0] == 101, "ring x[0] should be 101, got ${x[0]}")
    check(x[154] == 45, "ring x[154] should be 45, got ${x[154]}")
    // From 155 on the wrapping and non-wrapping forms agree, which is why a
    // spot check starting past the boundary catches nothing.
    check(x[155] == 0, "ring x[155] should be 0")
    check(x[156] == 1, "ring x[156] should be 1")
    // Plain Int arithmetic gives a NEGATIVE value here -- a third distinct
    // wrong answer, different from Python's 55.
    check((0 - 155) % 210 == -155, "plain Int gives -155, which would index out of range")
}

private fun testRotateOrZeroIsNotARotate() {
    check(FairPlaySapCore.rotateOrZero(0xAB, 0) == 0, "a zero count must yield 0")
    check(FairPlaySapCore.rotateOrZero(0xAB, 0) != 0xAB, "a zero count must NOT yield the input")
    check(FairPlaySapCore.rotateOrZero(0x81, 1) == 0x03, "a nonzero count rotates normally")
}

private fun testWideSeedIndexIsWiderThanAByte() {
    // If the index were masked to 8 bits these would agree everywhere.
    var differs = 0
    for (v in 0..255) for (c in 1..7) {
        val wide = (v shl c) or (v ushr (8 - c))
        if (wide % 21 != (wide and 0xFF) % 21) differs++
    }
    check(differs > 0, "masking wideSeed's index to 8 bits should change results")
}

private fun rows(path: String): List<List<String>> {
    val f = File(path)
    if (!f.exists()) {
        println("FAIL: $path is missing -- these tests fail rather than skip without it")
        failures++
        return emptyList()
    }
    return f.readLines().filter { it.isNotBlank() && !it.startsWith("#") }.map { it.split(",") }
}

private fun testSapHashCorpus(dir: String) {
    val r = rows("$dir/sap_hash.csv")
    var bad = 0
    for (p in r) if (str(FairPlaySapCore.sapHash(hex(p[0]))) != p[1]) bad++
    println("sap_hash corpus: ${r.size - bad}/${r.size}")
    check(r.isNotEmpty(), "the sap_hash corpus should not be empty")
    check(bad == 0, "every sap_hash vector should match")
}

private fun testBridgeCorpus(dir: String) {
    val r = rows("$dir/bridge_x9head.csv")
    var bad = 0
    for (p in r) if (str(FairPlaySapCore.bridgeX9HeadForSap(hex(p[0]), hex(p[1]))) != p[2]) bad++
    println("bridge_x9head corpus: ${r.size - bad}/${r.size}")
    check(r.isNotEmpty(), "the bridge corpus should not be empty")
    check(bad == 0, "every bridge vector should match")
}

fun main(args: Array<String>) {
    val dir = if (args.isNotEmpty()) args[0] else "../../conformance"
    testRingIndexUnderflowBoundary()
    testRotateOrZeroIsNotARotate()
    testWideSeedIndexIsWiderThanAByte()
    testSapHashCorpus(dir)
    testBridgeCorpus(dir)
    println("$checks checks, $failures failures")
    if (failures != 0) exitProcess(1)
}
