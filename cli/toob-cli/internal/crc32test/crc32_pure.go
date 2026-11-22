//go:build !cgo || !monorepo

package crc32test

const (
	crc32Poly     uint32 = 0xEDB88320
	crc32Init     uint32 = 0xFFFFFFFF
	crc32FinalXOR uint32 = 0xFFFFFFFF
)

var libCRC32NibbleTable = [16]uint32{
	0x00000000, 0x1DB71064, 0x3B6E20C8, 0x26D930AC,
	0x76DC4190, 0x6B6B51F4, 0x4DB26158, 0x5005713C,
	0xEDB88320, 0xF00F9344, 0xD6D6A3E8, 0xCB61B38C,
	0x9B64C2B0, 0x86D3D2D4, 0xA00AE278, 0xBDBDF21C,
}

// ComputeLibCRC32 computes IEEE 802.3 CRC-32 using the 16-entry nibble table
// matching sdk/libtoob/toob_crc32.c.
func ComputeLibCRC32(data []byte) uint32 {
	crc := crc32Init
	for _, b := range data {
		crc = (crc >> 4) ^ libCRC32NibbleTable[(crc^uint32(b))&0x0F]
		crc = (crc >> 4) ^ libCRC32NibbleTable[(crc^uint32(b>>4))&0x0F]
	}
	return crc ^ crc32FinalXOR
}

// ComputeBootCRC32 computes IEEE 802.3 CRC-32 using the table-less bitwise loop
// matching toobloader/core/utils/boot_crc32.c.
func ComputeBootCRC32(data []byte) uint32 {
	crc := crc32Init
	for _, b := range data {
		crc ^= uint32(b)
		for range 8 {
			if crc&1 != 0 {
				crc = (crc >> 1) ^ crc32Poly
			} else {
				crc >>= 1
			}
		}
	}
	return crc ^ crc32FinalXOR
}
