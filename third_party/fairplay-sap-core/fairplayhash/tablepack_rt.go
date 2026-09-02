// SPDX-License-Identifier: BlueOak-1.0.0

package fairplayhash

// unpackTable rebuilds one 256-byte table from its base and XOR masks:
// table[v] = base[v^inXor] ^ outXor.
func unpackTable(dst *[256]byte, bases, spec string) {
	base := bases[int(spec[0])*256:]
	inXor, outXor := spec[1], spec[2]
	for v := 0; v < 256; v++ {
		dst[v] = base[byte(v)^inXor] ^ outXor
	}
}
