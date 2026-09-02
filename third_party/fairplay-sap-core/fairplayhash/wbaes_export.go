// SPDX-License-Identifier: BlueOak-1.0.0

package fairplayhash

// WBAESTypeI and WBAESTypeII expose the white-box AES tables so pkg/fpbridge can
// use them without carrying a byte-identical second copy of 41 KB of data.
func WBAESTypeI() *[160][256]byte  { return &wbaesTypeI }
func WBAESTypeII() *[4][256]uint32 { return &wbaesTypeII }
