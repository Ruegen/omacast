// SPDX-License-Identifier: LGPL-3.0-or-later
//
// Conformance tests for FairPlaySapCore.cs.
//
// Build and run as a console app in this directory, excluding the other test
// file -- both declare an entry point and .NET will not take two:
//
//     <Compile Remove="FairPlayBridgeTest.cs" />
//     dotnet run -- ../../conformance
//
// Worth building with <CheckForOverflowUnderflow>true</CheckForOverflowUnderflow>,
// which this port is clean under. That is the C# analogue of running the Rust
// port in debug: it turns the deliberate unsigned wraps into runtime throws
// unless every one of them is inside an `unchecked` block.
//
// The expected values come from the CSV files in ../../conformance, generated
// by the Go reference in fpsapcore. Computing them here would make
// this a test that the code agrees with itself.

using System;
using System.IO;
using System.Linq;
using FairPlay;

internal static class FairPlaySapCoreTest
{
    private static int _checks;
    private static int _failures;

    private static void Check(bool ok, string what)
    {
        _checks++;
        if (!ok) { _failures++; Console.WriteLine("FAIL: " + what); }
    }

    private static byte[] Hex(string s)
    {
        var b = new byte[s.Length / 2];
        for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(s.Substring(i * 2, 2), 16);
        return b;
    }

    private static string Str(byte[] b) =>
        BitConverter.ToString(b).Replace("-", "").ToLowerInvariant();

    /// <summary>The unsigned-underflow trap.</summary>
    private static void TestRingIndexUnderflowBoundary()
    {
        FairPlaySapCore.BuildRingIndices(out var x, out _, out _, out var w);
        // 2^32 mod 210 == 46, and 55 + 46 == 101.
        Check(x[0] == 101, $"ring x[0] should be 101, got {x[0]}");
        Check(x[154] == 45, $"ring x[154] should be 45, got {x[154]}");
        // From 155 on, the wrapping and non-wrapping forms agree.
        Check(x[155] == 0, "ring x[155] should be 0");
        Check(x[156] == 1, "ring x[156] should be 1");
        Check(w[0] == 0, "ring w never underflows");
        // Signed int gives a NEGATIVE value -- a different wrong answer again.
        int si = 0;
        Check((si - 155) % 210 == -155, "signed int gives -155, which would index out of range");
    }

    private static void TestRotateOrZeroIsNotARotate()
    {
        Check(FairPlaySapCore.RotateOrZero(0xAB, 0) == 0, "a zero count must yield 0");
        Check(FairPlaySapCore.RotateOrZero(0xAB, 0) != 0xAB, "a zero count must NOT yield the input");
        Check(FairPlaySapCore.RotateOrZero(0x81, 1) == 0x03, "a nonzero count rotates normally");
    }

    private static void TestWideSeedIndexIsWiderThanAByte()
    {
        int differs = 0;
        for (uint v = 0; v < 256u; v++)
        {
            for (int c = 1; c < 8; c++)
            {
                uint wide = unchecked((v << c) | (v >> (8 - c)));
                if (wide % 21u != (wide & 0xFFu) % 21u) differs++;
            }
        }
        Check(differs > 0, "masking WideSeed's index to 8 bits should change results");
    }

    private static string[][] Rows(string path)
    {
        if (!File.Exists(path))
        {
            Console.WriteLine($"FAIL: {path} is missing -- these tests fail rather than skip without it");
            _failures++;
            return Array.Empty<string[]>();
        }
        return File.ReadLines(path)
            .Where(l => !string.IsNullOrWhiteSpace(l) && !l.StartsWith("#"))
            .Select(l => l.Split(','))
            .ToArray();
    }

    private static void TestSapHashCorpus(string dir)
    {
        var rows = Rows(Path.Combine(dir, "sap_hash.csv"));
        int bad = rows.Count(p => Str(FairPlaySapCore.SapHash(Hex(p[0]))) != p[1]);
        Console.WriteLine($"sap_hash corpus: {rows.Length - bad}/{rows.Length}");
        Check(rows.Length > 0, "the sap_hash corpus should not be empty");
        Check(bad == 0, "every sap_hash vector should match");
    }

    private static void TestBridgeCorpus(string dir)
    {
        var rows = Rows(Path.Combine(dir, "bridge_x9head.csv"));
        int bad = rows.Count(p =>
            Str(FairPlaySapCore.BridgeX9HeadForSap(Hex(p[0]), Hex(p[1]))) != p[2]);
        Console.WriteLine($"bridge_x9head corpus: {rows.Length - bad}/{rows.Length}");
        Check(rows.Length > 0, "the bridge corpus should not be empty");
        Check(bad == 0, "every bridge vector should match");
    }

    private static int Main(string[] args)
    {
        string dir = args.Length > 0 ? args[0] : "../../conformance";
        TestRingIndexUnderflowBoundary();
        TestRotateOrZeroIsNotARotate();
        TestWideSeedIndexIsWiderThanAByte();
        TestSapHashCorpus(dir);
        TestBridgeCorpus(dir);
        Console.WriteLine($"{_checks} checks, {_failures} failures");
        return _failures == 0 ? 0 : 1;
    }
}
