// SPDX-License-Identifier: BlueOak-1.0.0
/*
 * Minimal known-answer test for FairPlayBridge.cs.
 *
 * Build and run (as a console app in the same directory):
 *     dotnet run
 *
 * Vector generated from the reference implementation; the Go, Rust, C, Python
 * and Kotlin ports assert the same numbers, so all of them agree bit-for-bit.
 */
using System;

internal static class FairPlayBridgeTest
{
    private static void Main()
    {
        uint[] message =
        {
            2546976663u, 960577546u, 1698508769u, 1855391692u,
            3391201467u, 2557583070u, 3274602661u, 1912197568u,
            191961631u, 1855758578u, 4196764585u, 2306695412u,
            2755794883u, 994892358u, 790883565u, 349006184u,
        };
        uint[] want = { 0x3295ab96u, 0xea9e90ebu, 0x908160bdu, 0x2261d759u };

        uint[] state = (uint[])FairPlayBridge.InitialState.Clone();
        FairPlayBridge.Compress(state, message, FairPlayBridge.BridgeHash1Offset, FairPlayBridge.BridgeMutation.Kdf);

        bool ok = true;
        for (int i = 0; i < 4; i++)
        {
            if (state[i] != want[i]) ok = false;
        }

        if (!ok)
        {
            Console.Error.WriteLine(
                "FAIL: bridge_md5_compress KAT — got " +
                string.Join(",", Array.ConvertAll(state, x => x.ToString("x8"))));
            Environment.Exit(1);
        }

        Console.WriteLine("PASS: bridge_md5_compress KAT");
    }
}
