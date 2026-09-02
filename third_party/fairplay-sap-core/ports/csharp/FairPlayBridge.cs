// SPDX-License-Identifier: BlueOak-1.0.0
/*
 * FairPlayBridge.cs - standalone .NET bridge hash adapter.
 *
 * This is the recovered FairPlay SAP authentication primitive. It uses the
 * standard MD5 compression shape, standard message schedule, and the
 * standard RFC 1321 MD5 K table plus a per-hash-instance additive offset --
 * with one extra step: right after round 31, the message array is permuted
 * in place, and rounds 32-63 continue against the permuted array. The file
 * has no NuGet dependencies and works with ordinary uint[] arrays so it can
 * be dropped into older .NET projects too.
 *
 * It is not a complete payload-to-m3 responder. The remaining White-Box AES
 * data and fixed bridge tables are described in impact.md.
 */

using System;

public static class FairPlayBridge
{
    public static readonly uint[] InitialState =
    {
        0xB9F3DCDCu, 0xFBDC740Bu, 0x60F77F86u, 0x51907216u,
    };

    // Standard RFC 1321 MD5 per-round additive constant table. The bridge
    // hash's real per-round constant is StdMd5K[i] + offset, where offset
    // depends only on which hash-instance a block belongs to (see the
    // BridgeHash*Offset constants below) -- NOT a bespoke 64-entry table.
    private static readonly uint[] StdMd5K =
    {
        0xD76AA478u, 0xE8C7B756u, 0x242070DBu, 0xC1BDCEEEu,
        0xF57C0FAFu, 0x4787C62Au, 0xA8304613u, 0xFD469501u,
        0x698098D8u, 0x8B44F7AFu, 0xFFFF5BB1u, 0x895CD7BEu,
        0x6B901122u, 0xFD987193u, 0xA679438Eu, 0x49B40821u,
        0xF61E2562u, 0xC040B340u, 0x265E5A51u, 0xE9B6C7AAu,
        0xD62F105Du, 0x02441453u, 0xD8A1E681u, 0xE7D3FBC8u,
        0x21E1CDE6u, 0xC33707D6u, 0xF4D50D87u, 0x455A14EDu,
        0xA9E3E905u, 0xFCEFA3F8u, 0x676F02D9u, 0x8D2A4C8Au,
        0xFFFA3942u, 0x8771F681u, 0x6D9D6122u, 0xFDE5380Cu,
        0xA4BEEA44u, 0x4BDECFA9u, 0xF6BB4B60u, 0xBEBFBC70u,
        0x289B7EC6u, 0xEAA127FAu, 0xD4EF3085u, 0x04881D05u,
        0xD9D4D039u, 0xE6DB99E5u, 0x1FA27CF8u, 0xC4AC5665u,
        0xF4292244u, 0x432AFF97u, 0xAB9423A7u, 0xFC93A039u,
        0x655B59C3u, 0x8F0CCC92u, 0xFFEFF47Du, 0x85845DD1u,
        0x6FA87E4Fu, 0xFE2CE6E0u, 0xA3014314u, 0x4E0811A1u,
        0xF7537E82u, 0xBD3AF235u, 0x2AD7D2BBu, 0xEB86D391u,
    };

    // Per-hash-instance additive offsets, added to StdMd5K[i] for every
    // round of every block in that group.
    public const uint BridgeHash1Offset = 0xB36309E4u;      // Hash1's non-final blocks (first 4 of 5)
    public const uint BridgeHash1FinalOffset = 0x00000000u; // Hash1's final (5th) block: no offset
    public const uint BridgeHash2Offset = 0xD68864C0u;      // all 4 of Hash2's blocks

    // Which round-31-boundary message permutation a block uses.
    public enum BridgeMutation { Kdf, Cycle }

    private static void ApplyBridgeMutation(uint[] message, BridgeMutation variant, uint a, uint b, uint c, uint d)
    {
        void Swap(int i, int j)
        {
            uint tmp = message[i];
            message[i] = message[j];
            message[j] = tmp;
        }

        if (variant == BridgeMutation.Kdf)
        {
            Swap((int)(a & 15), (int)(b & 15));
            Swap((int)(c & 15), (int)(d & 15));
            foreach (int shift in new[] { 4, 8, 12 })
            {
                Swap((int)((a >> shift) & 15), (int)((b >> shift) & 15));
            }
        }
        else
        {
            int[] idx =
            {
                (int)(a & 15), (int)(b & 15), (int)(c & 15), (int)(d & 15),
                (int)((a >> 4) & 15), (int)((b >> 4) & 15), (int)((c >> 4) & 15), (int)((d >> 4) & 15),
            };
            uint first = message[idx[0]];
            for (int i = 0; i < idx.Length - 1; i++)
            {
                message[idx[i]] = message[idx[i + 1]];
            }
            message[idx[idx.Length - 1]] = first;
        }
    }

    private static readonly int[] Rotations =
    {
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    };

    private static readonly int[] Schedule =
    {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12,
        5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2,
        0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9,
    };

    public static void Compress(uint[] state, uint[] message, uint offset, BridgeMutation variant)
    {
        if (state == null || state.Length != 4) throw new ArgumentException("state must have four words");
        if (message == null || message.Length != 16) throw new ArgumentException("message must have sixteen words");

        unchecked
        {
            uint a = state[0], b = state[1], c = state[2], d = state[3];
            for (int i = 0; i < 64; i++)
            {
                uint function;
                if (i < 16) function = (b & c) | (~b & d);
                else if (i < 32) function = (d & b) | (~d & c);
                else if (i < 48) function = b ^ c ^ d;
                else function = c ^ (b | ~d);

                uint mixed = a + function + message[Schedule[i]] + StdMd5K[i] + offset;
                uint nextB = b + RotateLeft(mixed, Rotations[i]);
                a = d;
                d = c;
                c = b;
                b = nextB;

                if (i == 31)
                {
                    ApplyBridgeMutation(message, variant, a, b, c, d);
                }
            }

            state[0] += a;
            state[1] += b;
            state[2] += c;
            state[3] += d;
        }
    }

    private static uint RotateLeft(uint value, int amount)
    {
        return (value << amount) | (value >> (32 - amount));
    }
}
