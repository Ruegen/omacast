// SPDX-License-Identifier: LGPL-3.0-or-later
// Derived from github.com/omarroth/doubletake at 8ccea5f, via
// fpsapcore. See ../../NOTICE.md.
//
// FairPlaySapCore.cs - the FairPlay SAP Phase-1 bridge.
//
// FairPlayBridge.cs in this directory has the bridge *primitive*. This has the
// functions that feed it, so the two together are a complete responder:
//
//     FairPlaySapCore.BridgeX9HeadForSap(localSap, gp) -> byte[20]
//
// `gp` is Phase 1's 128-byte output buffer. The 20 bytes out are the only
// payload-dependent input Phase 2 consumes. No NuGet dependencies.
//
// --- FOUR THINGS THAT WILL BITE A PORT --------------------------------------
// Each of the first three is silent, and each fails 30+ of the 40 vectors in
// ../../conformance/.
//
//  1. Every arithmetic body here is `unchecked`. That is NOT decoration. The
//     ring index derivation underflows a uint on purpose, and a project built
//     with <CheckForOverflowUnderflow>true</CheckForOverflowUnderflow> throws
//     OverflowException without it. Measured, not assumed.
//  2. RotateOrZero returns 0 for a zero count, not the input. It is not a
//     rotate.
//  3. WideSeed's index is computed in uint, wider than a byte. Masking it to
//     8 bits changes the answer.
//  4. C# refuses to *compile* the constant form: `(uint)0 - 155` is
//     CS0220, "The operation overflows at compile time in checked mode". The
//     loops here compile because the operand is a variable, so the compiler
//     guards where you would write a test and not where the bug lives.
//
// Note also that byte arithmetic promotes to int, so results are cast back
// with (byte). Where the Go original deliberately computes in a wider type
// before dividing, the cast comes after the division and a comment says so.

using System;

namespace FairPlay
{
    public static class FairPlaySapCore
    {
        // --- byte helpers ---------------------------------------------------

        /// <summary>Rotate a byte left. Matches Go's bits.RotateLeft8.</summary>
        private static byte Rotl8(byte v, int n)
        {
            n &= 7;
            if (n == 0) return v;
            return unchecked((byte)((v << n) | (v >> (8 - n))));
        }

        /// <summary>
        /// Go's rotateOrZero: a count of 0 yields 0, NOT the input. This is the
        /// one rotate in the algorithm that is not a rotate.
        /// </summary>
        public static byte RotateOrZero(byte value, byte count)
        {
            if (count == 0) return 0;
            return Rotl8(value, count);
        }

        private static byte Majority(byte a, byte b, byte c)
            => unchecked((byte)(a ^ ((a ^ b) & (a ^ c))));

        private static byte SelectBits(byte mask, byte ifSet, byte ifClear)
            => unchecked((byte)(ifClear ^ ((ifSet ^ ifClear) & mask)));

        private static byte Square(byte v) => unchecked((byte)(v * v));

        private static byte Cube(byte v) => unchecked((byte)(v * v * v));

        /// <summary>Go's &amp;^ (AND NOT / bit clear). C# has no operator for it.</summary>
        private static byte AndNot(byte a, byte b) => unchecked((byte)(a & ~b));

        private static byte Not(byte v) => unchecked((byte)~v);

        // --- constants ------------------------------------------------------

        public static readonly byte[] SapSeed =
        {
            0xED, 0x25, 0xD1, 0xBB, 0xBC, 0x27, 0x9F, 0x02, 0xA2, 0xA9, 0x11,
            0x00, 0x0C, 0xB3, 0x52, 0xC0, 0xBD, 0xE3, 0x1B, 0x49, 0xC7,
        };

        private static readonly byte[] SapInitialHash =
        {
            0x96, 0x5F, 0xC6, 0x53, 0xF8, 0x46, 0xCC, 0x18, 0xDF, 0xBE,
            0xB2, 0xF8, 0x38, 0x62, 0xEC, 0x22, 0x93, 0xD1, 0x20, 0x8F,
        };

        private static readonly byte[] SapInitialMatrix =
        {
            0x43, 0x54, 0x62, 0x7A, 0x18, 0xC3, 0xD6, 0xB3, 0x9A, 0x56,
            0xF6, 0x1C, 0x14, 0x3F, 0x0C, 0x1D, 0x3B, 0x36, 0x83, 0xB1,
            0x39, 0x51, 0x4A, 0xAA, 0x09, 0x3E, 0xFE, 0x44, 0xAF, 0xDE,
            0xC3, 0x20, 0x9D, 0x42, 0xB8,
        };

        private static readonly byte[] FairplayInitialSessionKey =
        {
            0xDC, 0xDC, 0xF3, 0xB9, 0x0B, 0x74, 0xDC, 0xFB,
            0x86, 0x7F, 0xF7, 0x60, 0x16, 0x72, 0x90, 0x51,
        };

        private static readonly byte[] DescriptorPrefix =
        {
            0xA0, 0x44, 0x9C, 0x4D, 0x09, 0xE4, 0xBD, 0x7F, 0x6E,
            0xC5, 0xD0, 0xCC, 0x35, 0x9D, 0xA7, 0x46, 0x7A,
        };

        private static readonly byte[] DescriptorSuffix =
        {
            0x97, 0xB5, 0x0F, 0x84, 0xE2, 0x15, 0x5A, 0x9C, 0x24,
            0x99, 0x1C, 0xF4, 0x3A, 0x09, 0x63, 0x55, 0x47,
        };

        /// <summary>
        /// The white-box output encoding Phase 1 leaves on the GP buffer: one
        /// XOR constant across all 128 bytes. Measured, not assumed.
        /// </summary>
        public const byte GpOutputMask = 0x0F;

        /// <summary>
        /// Go's wideSeed. The index is computed in uint, WIDER than a byte:
        /// value &lt;&lt; count may exceed 255 before the modulo. Masking it to
        /// 8 bits changes the result.
        /// </summary>
        public static byte WideSeed(byte value, byte count)
        {
            if (count == 0) return SapSeed[0];
            uint wide = unchecked(((uint)value << count) | ((uint)value >> (8 - count)));
            return SapSeed[wide % 21u];
        }

        // --- the ring index tables ------------------------------------------

        /// <summary>
        /// The four index sequences. The subtraction underflows a uint on
        /// purpose; `unchecked` is what allows it, and without it this throws
        /// OverflowException in a checked build.
        /// </summary>
        public static void BuildRingIndices(
            out byte[] x, out byte[] y, out byte[] z, out byte[] w)
        {
            x = new byte[840];
            y = new byte[840];
            z = new byte[840];
            w = new byte[840];
            unchecked
            {
                for (uint i = 0; i < 840u; i++)
                {
                    x[i] = (byte)((i - 155u) % 210u);
                    y[i] = (byte)((i - 57u) % 210u);
                    z[i] = (byte)((i - 13u) % 210u);
                    w[i] = (byte)(i % 210u);
                }
            }
        }

        /// <summary>work is three copies of the permuted block plus its first 18 bytes.</summary>
        private static byte[] FillWork(byte[] block)
        {
            var p = new byte[64];
            for (int i = 0; i < 64; i++) p[i] = block[i ^ 3];
            var work = new byte[210];
            Buffer.BlockCopy(p, 0, work, 0, 64);
            Buffer.BlockCopy(p, 0, work, 64, 64);
            Buffer.BlockCopy(p, 0, work, 128, 64);
            Buffer.BlockCopy(p, 0, work, 192, 18);
            return work;
        }

        // --- the SAP hash ---------------------------------------------------

        /// <summary>
        /// FairPlay's proprietary SAP hash of one 64-byte block. Not a standard
        /// hash.
        /// </summary>
        public static byte[] SapHash(byte[] block)
        {
            if (block == null || block.Length != 64)
                throw new ArgumentException("block must be 64 bytes", nameof(block));

            BuildRingIndices(out var rx, out var ry, out var rz, out var rw);

            var hash = (byte[])SapInitialHash.Clone();
            var matrix = (byte[])SapInitialMatrix.Clone();
            var aux = new byte[10];
            var work = FillWork(block);

            unchecked
            {
                for (int i = 0; i < 840; i++)
                {
                    byte xv = work[rx[i]], yv = work[ry[i]], zv = work[rz[i]];
                    int wi = rw[i];
                    work[wi] = (byte)(Rotl8(yv, 5) + (Rotl8(zv, 3) ^ work[wi]) - Rotl8(xv, 7));
                }

                NonlinearCircuit(hash, matrix, aux, work);

                var outBytes = new byte[16];
                // Go: copy(out[:], aux[:3]) then copy(out[4:], aux[3:]) - 3 then 7.
                Array.Copy(aux, 0, outBytes, 0, 3);
                Array.Copy(aux, 3, outBytes, 4, 7);
                for (int i = 0; i < 16; i++) outBytes[i] = (byte)(outBytes[i] + 0xE1);
                outBytes[3] = 0x3D;
                outBytes[11] = 0x3C;
                outBytes[10] ^= (byte)(aux[3] ^ 133);

                for (int i = 0; i < 20; i++)
                    outBytes[i & 15] ^= (byte)(work[i] ^ matrix[i] ^ hash[i]);
                for (int i = 20; i < 35; i++)
                    outBytes[i & 15] ^= (byte)(work[i] ^ matrix[i]);
                for (int i = 35; i < 210; i++)
                    outBytes[i & 15] ^= work[i];

                ApplyScramble(outBytes);
                return outBytes;
            }
        }

        /// <summary>
        /// 256 rounds of XOR-and-rotate, in place over 16 bytes. Every operation
        /// is GF(2)-linear, so this collapses to a 128x128 binary matrix - which
        /// is what the Go version ships for speed. The loop is kept here because
        /// a snippet is for reading, and the matrix is 2 KB of opaque data.
        /// </summary>
        public static void ApplyScramble(byte[] outBytes)
        {
            unchecked
            {
                for (int i = 0; i < 256; i++)
                {
                    outBytes[i & 15] ^= (byte)(
                        Rotl8(outBytes[(i - 7) & 15], 1)
                        ^ Rotl8(outBytes[(i - 5) & 15], 6)
                        ^ Rotl8(outBytes[(i - 1) & 15], 5));
                }
            }
        }

        /// <summary>
        /// The straight-line byte circuit. Statement order is load-bearing:
        /// several lines assign to a cell a later line reads, and matrix[12] is
        /// written three times. Reordering for tidiness breaks it.
        /// </summary>
        private static void NonlinearCircuit(
            byte[] hash, byte[] matrix, byte[] aux, byte[] work)
        {
            byte Hi(int i) => hash[(byte)i % 20];
            byte Si(int i) => SapSeed[(byte)i % 21];
            byte H(int i) => Hi(work[i]);
            byte M(int i) => matrix[work[i] % 35];
            byte S(int i) => Si(work[i]);
            byte Ma(int i) => matrix[aux[i] % 35];

            unchecked
            {
                matrix[12] = (byte)(0x14 + (SelectBits(92, work[64], (byte)(work[99] / 3))
                                            & WideSeed(S(206), 4)));
                work[4] = (byte)(2 * Square((byte)(work[99] / 5)));
                work[153] ^= (byte)(Square(M(203)) * work[190]);
                hash[3] = (byte)(0x13 ^ ((S(205) >> 1) & 0x10));
                work[33] = (byte)(work[33] - AndNot(S(36), 9));
                aux[5] = (byte)((AndNot(M(67), 2) | 1 | ((H(181) >> 6) & 2)
                                 | (hash[3] & 0x10)) - 15);
                matrix[12] = 0x07;
                work[2] = (byte)(work[2] - 64);
                hash[19] = S(58);
                aux[4] = (byte)(92 - M(32));
                aux[9] = (byte)(M(15) + 0x9E);
                work[34] = (byte)(work[34] + Si(aux[9]) / 5);
                hash[19] = (byte)(hash[19] + (0xE6 ^ ((Hi(aux[9]) >> 1) & 0x66)));
                work[15] ^= (byte)(3 * RotateOrZero(work[72], (byte)(-S(190) & 7))
                                   - 9 * S(126));
                hash[15] ^= Cube(M(181));
                matrix[4] ^= (byte)(work[202] / 3);
                matrix[1] = (byte)(matrix[1] + Cube(Majority((byte)(92 - Hi(aux[4])),
                                                             Not(work[105]), 0xC6)));
                // int math, then truncate
                hash[19] ^= (byte)(((uint)(224 | (S(92) & 27)) * M(41)) / 3u);
                work[140] = (byte)(work[140] + RotateOrZero(92, (byte)(-work[5] & 7)));
                matrix[12] = (byte)(matrix[12] + Majority((byte)(Not(work[4]) ^ M(12)),
                                                          work[182], 192));
                work[36] = (byte)(work[36] + 125);
                work[124] = Rotl8(Majority(Majority(work[138], hash[15], 74), H(43), 95), 4);
                byte auxHash = Hi(aux[9]);
                aux[1] = AndNot(0x4C, (byte)(auxHash & (byte)(S(68) << 1)));
                aux[2] = (byte)(222 - Majority(
                    (byte)(((uint)work[177] + S(79)) >> 1),
                    (byte)(3u * work[148] / 5u),
                    matrix[1]));
                matrix[16] = (byte)(matrix[16] + ((AndNot(Ma(4), 0x60) | auxHash | 8)
                                                  - (Rotl8(work[33], 2) | 128)));
                hash[14] ^= Ma(2);
                work[19] = (byte)(work[19] + Majority(
                    RotateOrZero(Si(H(201)), (byte)((M(112) << 1) & 6)),
                    (byte)((AndNot(H(208), 0x7C) | (H(164) & 0x7C)) / 5),
                    37));
                matrix[8] = (byte)(RotateOrZero(140, (byte)(-Square(S(45)) & 7)) ^ aux[4]);
                work[190] = 56;
                work[53] = Not((byte)((H(83) | 204) / 5));
                hash[13] = (byte)(hash[13] + H(41));
                hash[10] = (byte)(Majority(Ma(4), work[2], aux[2]) / 15);
                aux[3] = (byte)(92 - Square((byte)(0x28 | (Ma(1) & (0x12 | (S(2) & 4))))));
                byte seedBits = Si(aux[4]);
                matrix[13] ^= seedBits;
                aux[6] = (byte)(92 + Square(Majority((byte)(M(179) - 38), aux[2], 177)));
                byte expansionBits = Majority((byte)(aux[3] + (aux[4] & 74)),
                                              Not(seedBits), 121);
                work[47] ^= (byte)(M(89) + Majority((byte)(expansionBits ^ 0xA6), aux[4], 4));
                aux[7] = (byte)(seedBits / 3 - Ma(9)
                                - (0x14 | (work[151] & ((aux[4] & 0x88) | 0x62))
                                   | (aux[4] & 0x22)));
                byte expandedSelector = (byte)(expansionBits ^ ((aux[4] & 0xCA) >> 1) ^ 75);
                aux[9] = (byte)(aux[9] + (0x80 | (Majority(aux[7], work[151], 0x20) & 0x64)
                                          | (seedBits & 0x44) | (Ma(9) & 0x1B)));
                matrix[33] ^= work[26];
                matrix[30] = (byte)((byte)(aux[9] / 3 - (AndNot(aux[4], 8) | 0x13)) ^ H(122));
                work[22] = (byte)((M(90) & 0x1B) | 0x44);
                uint wide = SelectBits(71, matrix[expandedSelector % 35], Si(aux[5]));
                // int math, then truncate
                matrix[18] = (byte)(matrix[18] + (byte)((wide * wide * wide) >> 1));
                matrix[5] = (byte)(matrix[5] - S(92));
                matrix[18] ^= (byte)(SelectBits(aux[3], Ma(3),
                                                SelectBits(16, M(183), work[41]))
                                     * SelectBits(expandedSelector, H(59), work[17]));
                matrix[22] = (byte)(Majority(
                    SelectBits((byte)(hash[14] | 28), (byte)((work[7] & 28) | 0x82), H(93)),
                    RotateOrZero(Ma(4),
                        (byte)(RotateOrZero(work[11], (byte)(-M(28) & 7)) & 7)),
                    matrix[33]) + 74);
                hash[15] = (byte)(hash[15] - Majority(Majority(aux[3], aux[4], 214),
                                                      Si((byte)(H(39) ^ 217)), aux[6]));

                byte hash9 = Hi(aux[9]);
                byte indexedHash = Hi((byte)((byte)(aux[4] / 3 - (aux[9] | work[22]))
                    ^ aux[6]
                    ^ (((M(57) | hash9) & (0x52 | (aux[9] & 0x0D)))
                       | (((M(57) & hash9) | aux[9]) & 0x20))));
                aux[6] = (byte)(Square(Square(H(99))) | Ma(9));
                aux[1] = (byte)(aux[1]
                    + RotateOrZero((byte)(H(151) | S(202)), (byte)(H(50) & 7))
                    + Majority(H(4),
                        (byte)(((uint)SelectBits(matrix[16], indexedHash, M(138))
                                + SelectBits(17, work[33], S(39))) / 5u),
                        147));
                aux[0] = SelectBits((byte)(hash[10] & 7),
                                    (byte)(Ma(6) & H(209)),
                                    SelectBits(0x47,
                                        RotateOrZero(S(127), (byte)(Ma(6) & 7)),
                                        (byte)(Si(Ma(5)) << 1)));
                byte selectedSquare = SelectBits(198, Square(M(14)), (byte)(H(145) ^ aux[0]));
                byte seed9 = Si(aux[9]);
                byte hash3 = Hi(aux[3]);
                matrix[2] = (byte)(matrix[2] + (((byte)(hash3 << 1)
                                                 & ((work[25] & 0x96) | (seed9 & 8)))
                                                | (seed9 & 0x40)));
                matrix[14] = (byte)(matrix[14] - SelectBits(34, work[97],
                                        (byte)(Ma(3) & (aux[0] ^ M(100)))));
                work[23] ^= (byte)(Majority(Majority(S(17), hash3, aux[0]),
                                            (byte)(work[50] / 3), 0x76) << 1);
                hash[17] = 115;
                hash[13] = (byte)(((Majority(Hi(aux[7]), work[10], 82) >> 1) & 0x68)
                                  | (H(39) & 0x17));
                matrix[33] = (byte)(matrix[33] - (work[113] & 9));
                matrix[28] = (byte)(matrix[28] - (AndNot(aux[3], 0x20)
                                                  | ((work[110] >> 1) & 0x20)));
                work[95] = Si(aux[3]);
                hash[15] = (byte)(Majority((byte)(work[95] - 48), Not(work[184]), 189)
                                  & Cube(Majority(aux[7], Si(aux[1]), 0xAA)));
                matrix[22] = (byte)(matrix[22] + work[183]);
                aux[4] ^= (byte)(3 * S(1));
                aux[5] = (byte)(aux[5] + 198 * Majority(S(178), Ma(1), 209) * H(13)
                                * (S(26) >> 1));
                aux[8] = SelectBits(10, Ma(3), Ma(9));
                matrix[18] = (byte)(matrix[18] - SelectBits(hash[15], (byte)(aux[5] / 15),
                                        Cube((byte)(Hi(aux[6]) | 81))));
                aux[1] = (byte)(aux[1] + Si(Hi(aux[1])) / 3 - H(160));
                hash[16] = (byte)(147 - Majority(aux[0],
                    Majority(S(69), work[172], (byte)(aux[2] - selectedSquare + 77)),
                    (byte)(0xC2 | (aux[0] & 5))));
                hash[3] = (byte)(hash[3] - WideSeed(Majority(S(155), work[105], 141),
                                      (byte)(Majority(S(168), H(29), 6) & 7)));
                work[5] = (byte)(RotateOrZero(0x38, (byte)(-(byte)(H(61) / 5) & 7))
                                 ^ (byte)(Not(Ma(8)) / 5));
                work[198] = (byte)(work[198] + work[3]);
                wide = (uint)(162 | Ma(9));
                // int math, then truncate
                work[164] = (byte)(work[164] + (byte)((wide * wide) / 5u));
                aux[2] = (byte)(Majority(RotateOrZero(139, (byte)(-aux[5] & 6)),
                                         Hi(aux[3]), 12)
                                | SelectBits(95, Cube(seed9), Hi(aux[7])));
                matrix[12] = (byte)(matrix[12] + (byte)((16 | ((work[103] | 60)
                                        & (aux[2] | (work[103] & 32)))) / 3));
                work[143] = (byte)(work[143] - (0x12 | (SelectBits(aux[9],
                                        SelectBits(matrix[8], work[35], aux[7]),
                                        (byte)(aux[8] / 3))
                                    & (0x4D | ((work[172] >> 1) & 0x20)))));
                matrix[29] = 162;
                hash[15] = (byte)(hash[15] + Majority((byte)(M(149) ^ Square(work[43])),
                                        (byte)(SelectBits(95, H(125), Si(aux[1])) >> 1),
                                        115));
                aux[9] = (byte)(aux[9] - Hi(aux[7]));
                hash[7] = (byte)(hash[7] - Square(RotateOrZero(Ma(5),
                                        (byte)(-(byte)(M(17) * (M(17) & 1))))));
                matrix[8] = (byte)(matrix[8] + Cube(S(202)) - work[184]);
                hash[16] = (byte)((M(102) << 1) & 0x84);
                aux[6] ^= (byte)(Si(aux[7]) >> 1);
                hash[7] = (byte)(hash[7] - H(191)
                                 + SelectBits(177, Si(Si(aux[1])), (byte)(S(80) << 1)));
                hash[6] = H(119);
                hash[12] = (byte)((Hi(aux[8]) ^ (byte)(M(71) + M(15)))
                                  & Majority((byte)(AndNot(work[118], 0x2C) | 2),
                                             Square(Hi(aux[9])), 27));
                byte digestIndex = (byte)(SelectBits(0xA9, (byte)(S(57) * 231),
                                              Majority(work[32], Ma(1), 23)) / 5);
                byte seedSample = Si(aux[6]);
                aux[5] = (byte)(Majority((byte)((seedSample & 0x1C) | (H(82) & 0xA2)
                                                | (Si(digestIndex) & 0x41)),
                                         Majority(Cube(Hi(aux[7])), work[82], 92), 192)
                                ^ digestIndex);
                matrix[25] ^= (byte)(2 * Hi(aux[9]) * work[5]
                                     - (RotateOrZero(aux[4], (byte)(seedSample & 7))
                                        & (byte)(aux[3] + 110)));
            }
        }

        // --- the FairPlay MD5 family ----------------------------------------

        private static readonly int[] Md5Shift =
        {
            7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
            5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
            4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
            6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
        };

        private static readonly uint[] Md5Constant =
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

        private static uint Rotl32(uint v, int n)
        {
            n &= 31;
            if (n == 0) return v;
            return unchecked((v << n) | (v >> (32 - n)));
        }

        /// <summary>
        /// Standard MD5 rounds and constants, but big-endian message words and a
        /// message-schedule mutation after round 31. System.Security.Cryptography.MD5
        /// cannot do this.
        /// </summary>
        private static void Md5Compress(uint[] state, byte[] padded, int off)
        {
            unchecked
            {
                var message = new uint[16];
                for (int i = 0; i < 16; i++)
                {
                    message[i] = ((uint)padded[off + i * 4] << 24)
                               | ((uint)padded[off + i * 4 + 1] << 16)
                               | ((uint)padded[off + i * 4 + 2] << 8)
                               | padded[off + i * 4 + 3];
                }

                uint a = state[0], b = state[1], c = state[2], d = state[3];

                for (int round = 0; round < 64; round++)
                {
                    uint f;
                    int word;
                    if (round < 16) { f = (b & c) | (~b & d); word = round; }
                    else if (round < 32) { f = (d & b) | (~d & c); word = (5 * round + 1) & 15; }
                    else if (round < 48) { f = b ^ c ^ d; word = (3 * round + 5) & 15; }
                    else { f = c ^ (b | ~d); word = (7 * round) & 15; }

                    uint nextB = b + Rotl32(a + f + Md5Constant[round] + message[word],
                                            Md5Shift[round]);
                    // Go: a, b, c, d = d, nextB, b, c - one simultaneous rotation.
                    uint prevB = b, prevC = c;
                    a = d; d = prevC; c = prevB; b = nextB;

                    if (round == 31) MutateMessage(message, a, b, c, d);
                }

                state[0] += a; state[1] += b; state[2] += c; state[3] += d;
            }
        }

        /// <summary>
        /// Only the cycle mutation is reachable from the descriptor; the swap and
        /// KDF variants live in the Go reference.
        /// </summary>
        private static void MutateMessage(uint[] message, uint a, uint b, uint c, uint d)
        {
            var idx = new[]
            {
                (int)(a & 15), (int)(b & 15), (int)(c & 15), (int)(d & 15),
                (int)((a >> 4) & 15), (int)((b >> 4) & 15),
                (int)((c >> 4) & 15), (int)((d >> 4) & 15),
            };
            uint first = message[idx[0]];
            for (int i = 0; i < idx.Length - 1; i++) message[idx[i]] = message[idx[i + 1]];
            message[idx[idx.Length - 1]] = first;
        }

        // --- the descriptor and the bridge ----------------------------------

        /// <summary>The 20-byte descriptor over prefix || m3Sap || m2Sap || suffix.</summary>
        public static byte[] DescriptorForSap(byte[] m3Sap, byte[] m2Sap)
        {
            if (m3Sap == null || m3Sap.Length != 128)
                throw new ArgumentException("m3Sap must be 128 bytes", nameof(m3Sap));
            if (m2Sap == null || m2Sap.Length != 128)
                throw new ArgumentException("m2Sap must be 128 bytes", nameof(m2Sap));

            unchecked
            {
                var padded = new byte[320];
                int off = 0;
                Array.Copy(DescriptorPrefix, 0, padded, off, 17); off += 17;
                Array.Copy(m3Sap, 0, padded, off, 128); off += 128;
                Array.Copy(m2Sap, 0, padded, off, 128); off += 128;
                Array.Copy(DescriptorSuffix, 0, padded, off, 17); off += 17;
                padded[off] = 0x80;
                ulong bits = (ulong)off * 8u;
                for (int i = 0; i < 8; i++) padded[312 + i] = (byte)(bits >> (8 * i));

                var state = new uint[4];
                for (int i = 0; i < 4; i++)
                {
                    state[i] = FairplayInitialSessionKey[i * 4]
                             | ((uint)FairplayInitialSessionKey[i * 4 + 1] << 8)
                             | ((uint)FairplayInitialSessionKey[i * 4 + 2] << 16)
                             | ((uint)FairplayInitialSessionKey[i * 4 + 3] << 24);
                }
                var firstFinal = new uint[4];

                var block = new byte[64];
                for (int blockOff = 0; blockOff < 320; blockOff += 64)
                {
                    Array.Copy(padded, blockOff, block, 0, 64);
                    var add = SapHash(block);
                    for (int i = 0; i < 4; i++)
                    {
                        state[i] += add[i * 4]
                                  | ((uint)add[i * 4 + 1] << 8)
                                  | ((uint)add[i * 4 + 2] << 16)
                                  | ((uint)add[i * 4 + 3] << 24);
                    }
                    Md5Compress(state, padded, blockOff);
                    if (blockOff == 320 - 64)
                    {
                        Array.Copy(state, firstFinal, 4);
                        Md5Compress(state, padded, blockOff);
                    }
                }

                var result = new byte[20];
                result[0] = (byte)(firstFinal[0] >> 24);
                result[1] = (byte)(firstFinal[0] >> 16);
                result[2] = (byte)(firstFinal[0] >> 8);
                result[3] = (byte)firstFinal[0];
                for (int i = 0; i < 4; i++)
                {
                    result[4 + i * 4] = (byte)(state[i] >> 24);
                    result[4 + i * 4 + 1] = (byte)(state[i] >> 16);
                    result[4 + i * 4 + 2] = (byte)(state[i] >> 8);
                    result[4 + i * 4 + 3] = (byte)state[i];
                }
                return result;
            }
        }

        /// <summary>
        /// The 20 payload-dependent bytes Phase 2 consumes, for a per-session SAP.
        /// `gp` is Phase 1's 128-byte output buffer.
        /// </summary>
        public static byte[] BridgeX9HeadForSap(byte[] localSap, byte[] gp)
        {
            if (gp == null || gp.Length != 128)
                throw new ArgumentException("gp must be 128 bytes", nameof(gp));

            var body = new byte[128];
            for (int i = 0; i < 128; i++) body[i] = unchecked((byte)(gp[i] ^ GpOutputMask));
            var d = DescriptorForSap(localSap, body);
            // The descriptor emits big-endian words; x9Data is little-endian.
            var result = new byte[20];
            for (int w = 0; w < 5; w++)
                for (int b = 0; b < 4; b++)
                    result[w * 4 + b] = d[w * 4 + 3 - b];
            return result;
        }
    }
}
