//go:build cgo && monorepo

package crc32test

/*
#cgo CFLAGS: -I${SRCDIR}/../../../../sdk/libtoob -I${SRCDIR}/../../../../sdk/libtoob/include -I${SRCDIR}/../../../../common/include -I${SRCDIR}/../../../../toobloader/core/include -I${SRCDIR}/../../../../toobloader/core/utils/include

#include <stdint.h>
#include <stddef.h>

#include "../../../../sdk/libtoob/toob_crc32.c"
#include "../../../../toobloader/core/utils/boot_crc32.c"
#include "../../../../toobloader/core/utils/boot_secure_zeroize_host.c"
*/
import "C"
import "unsafe"

// ComputeLibCRC32 computes CRC32 using the libtoob C implementation.
func ComputeLibCRC32(data []byte) uint32 {
	if len(data) == 0 {
		return uint32(C.toob_lib_crc32(nil, 0))
	}
	return uint32(C.toob_lib_crc32((*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data))))
}

// ComputeBootCRC32 computes CRC32 using the bootloader C implementation.
func ComputeBootCRC32(data []byte) uint32 {
	if len(data) == 0 {
		return uint32(C.compute_boot_crc32(nil, 0))
	}
	return uint32(C.compute_boot_crc32((*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data))))
}
