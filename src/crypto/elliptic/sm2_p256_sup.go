// Some values and funcs are not defined when platform is amd64 or arm64

//go:build amd64 || arm64
// +build amd64 arm64

package elliptic

const bottom29Bits = 0x1FFFFFFF

// nonZeroToAllOnes returns:
//   0xffffffff for 0 < x <= 2**31
//   0 for x == 0 or x > 2**31.
func nonZeroToAllOnes(x uint32) uint32 {
	return ((x - 1) >> 31) - 1
}
