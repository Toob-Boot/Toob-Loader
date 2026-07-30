package tbm1

// #cgo CFLAGS: -I${SRCDIR}/../../../../common/include
// #cgo CFLAGS: -I${SRCDIR}/../../../../toobloader/core/include
// #cgo CFLAGS: -I${SRCDIR}/../../../../toobloader/core/utils/include
// #cgo CFLAGS: -std=c11 -Wall -Wextra -Wno-unused-parameter
//
// extern int toob_admit_validate(const unsigned char *buf,
//                                unsigned int buf_len,
//                                unsigned int staging_cap);
import "C"
import (
	"fmt"
	"unsafe"
)

// RejectCode maps 1:1 to tbm1_reject_t from boot_tbm1.h.
// The values must stay in sync with the C enum.
type RejectCode int

const (
	RejectOK             RejectCode = 0
	RejectBadMagic       RejectCode = 1
	RejectBadFixedLen    RejectCode = 2
	RejectBadVersion     RejectCode = 3
	RejectBadTotalLen    RejectCode = 4
	RejectBadAlign       RejectCode = 5
	RejectBadCRC         RejectCode = 6
	RejectBadCritFlag    RejectCode = 7
	RejectBadReaderVer   RejectCode = 8
	RejectBadImageCount  RejectCode = 9
	RejectBadKeyIndex    RejectCode = 10
	RejectBadHWCompat    RejectCode = 11
	RejectBadChunkMath   RejectCode = 12
	RejectBadImageField  RejectCode = 13
	RejectBadRegionBounds RejectCode = 14
	RejectBadRegionOrder RejectCode = 15
	RejectBadRegionDup   RejectCode = 16
	RejectBadChunkHashLen RejectCode = 17
	RejectBadRegionAlign RejectCode = 18
)

var rejectNames = [...]string{
	"TBM1_OK",
	"TBM1_BAD_MAGIC",
	"TBM1_BAD_FIXED_LEN",
	"TBM1_BAD_VERSION",
	"TBM1_BAD_TOTAL_LEN",
	"TBM1_BAD_ALIGN",
	"TBM1_BAD_CRC",
	"TBM1_BAD_CRIT_FLAG",
	"TBM1_BAD_READER_VERSION",
	"TBM1_BAD_IMAGE_COUNT",
	"TBM1_BAD_KEY_INDEX",
	"TBM1_BAD_HW_COMPAT",
	"TBM1_BAD_CHUNK_MATH",
	"TBM1_BAD_IMAGE_FIELD",
	"TBM1_BAD_REGION_BOUNDS",
	"TBM1_BAD_REGION_ORDER",
	"TBM1_BAD_REGION_DUP",
	"TBM1_BAD_CHUNKHASH_LEN",
	"TBM1_BAD_REGION_ALIGN",
}

func (r RejectCode) String() string {
	if int(r) >= 0 && int(r) < len(rejectNames) {
		return rejectNames[r]
	}
	return fmt.Sprintf("TBM1_UNKNOWN(%d)", int(r))
}

// ValidateCReader runs the bootloader's C-Reader over a raw TBM1 blob.
//
// stagingCap is the staging area capacity of the target. Pass 0 to use
// the blob length itself as the capacity bound (no artificial cap).
//
// Returns RejectOK on success, or the specific reject code on failure.
func ValidateCReader(blob []byte, stagingCap uint32) RejectCode {
	if len(blob) < FixedLen {
		return RejectBadMagic
	}

	cap := stagingCap
	if cap == 0 {
		cap = uint32(len(blob))
	}

	rc := C.toob_admit_validate(
		(*C.uchar)(unsafe.Pointer(&blob[0])),
		C.uint(len(blob)),
		C.uint(cap),
	)

	return RejectCode(rc)
}
