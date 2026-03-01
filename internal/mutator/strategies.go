package mutator

import (
	"fmt"
	"math/big"
	"math/rand"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

// precompileAddresses includes Ethereum precompile contract addresses (0x01–0x09).
var precompileAddresses = []common.Address{
	common.HexToAddress("0x01"),
	common.HexToAddress("0x02"),
	common.HexToAddress("0x03"),
	common.HexToAddress("0x04"),
	common.HexToAddress("0x05"),
	common.HexToAddress("0x06"),
	common.HexToAddress("0x07"),
	common.HexToAddress("0x08"),
	common.HexToAddress("0x09"),
}

// powersOfTwo holds 2^0 through 2^255 for uint boundary testing.
var powersOfTwo [256]*big.Int

func init() {
	for i := 0; i < 256; i++ {
		powersOfTwo[i] = new(big.Int).Lsh(big.NewInt(1), uint(i))
	}
}

// generateValue produces a value for t. If boundary is true, it picks an edge value;
// otherwise it generates a random value within type bounds.
func generateValue(rng *rand.Rand, t abi.Type, accounts []common.Address, boundary bool) (interface{}, error) {
	switch t.T {
	case abi.UintTy:
		return genUint(rng, t.Size, boundary), nil

	case abi.IntTy:
		return genInt(rng, t.Size, boundary), nil

	case abi.BoolTy:
		if boundary {
			return rng.Intn(2) == 0, nil
		}
		return rng.Intn(2) == 0, nil

	case abi.AddressTy:
		return genAddress(rng, accounts, boundary), nil

	case abi.BytesTy:
		return genBytes(rng, boundary), nil

	case abi.FixedBytesTy:
		return genFixedBytes(rng, t.Size, boundary), nil

	case abi.StringTy:
		b := genBytes(rng, boundary)
		return string(b), nil

	case abi.SliceTy:
		return genSlice(rng, t, accounts, boundary)

	case abi.ArrayTy:
		return genArray(rng, t, accounts, boundary)

	case abi.TupleTy:
		return genTuple(rng, t, accounts, boundary)

	default:
		return nil, fmt.Errorf("unsupported ABI type: %v (T=%d)", t.String(), t.T)
	}
}

// --- uint ---

func genUint(rng *rand.Rand, bits int, boundary bool) *big.Int {
	max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(bits)), big.NewInt(1))

	if boundary {
		candidates := []*big.Int{
			big.NewInt(0),
			big.NewInt(1),
			big.NewInt(2),
			new(big.Int).Set(max),
			new(big.Int).Sub(max, big.NewInt(1)),
		}
		// Add powers of two that fit
		for _, p := range powersOfTwo[:bits] {
			if p.Cmp(max) <= 0 {
				candidates = append(candidates, new(big.Int).Set(p))
			}
		}
		return new(big.Int).Set(candidates[rng.Intn(len(candidates))])
	}

	n := new(big.Int)
	n.Rand(rng, new(big.Int).Add(max, big.NewInt(1)))
	return n
}

// --- int (signed) ---

func genInt(rng *rand.Rand, bits int, boundary bool) *big.Int {
	// Range: [-2^(bits-1), 2^(bits-1)-1]
	maxPos := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(bits-1)), big.NewInt(1))
	minNeg := new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), uint(bits-1)))

	if boundary {
		candidates := []*big.Int{
			big.NewInt(0),
			big.NewInt(1),
			big.NewInt(-1),
			new(big.Int).Set(maxPos),
			new(big.Int).Sub(maxPos, big.NewInt(1)),
			new(big.Int).Set(minNeg),
			new(big.Int).Add(minNeg, big.NewInt(1)),
		}
		return new(big.Int).Set(candidates[rng.Intn(len(candidates))])
	}

	// Random in [minNeg, maxPos]
	rangeSize := new(big.Int).Sub(maxPos, minNeg)
	rangeSize.Add(rangeSize, big.NewInt(1))
	n := new(big.Int).Rand(rng, rangeSize)
	n.Add(n, minNeg)
	return n
}

// --- address ---

func genAddress(rng *rand.Rand, accounts []common.Address, boundary bool) common.Address {
	if boundary {
		candidates := []common.Address{
			common.Address{}, // zero address
		}
		candidates = append(candidates, precompileAddresses...)
		candidates = append(candidates, accounts...)
		return candidates[rng.Intn(len(candidates))]
	}

	if len(accounts) > 0 && rng.Intn(3) != 0 {
		return accounts[rng.Intn(len(accounts))]
	}
	// Fully random address
	var addr common.Address
	rng.Read(addr[:])
	return addr
}

// --- bytes (dynamic) ---

func genBytes(rng *rand.Rand, boundary bool) []byte {
	if boundary {
		switch rng.Intn(4) {
		case 0:
			return []byte{} // empty
		case 1:
			return []byte{0x00}
		case 2:
			// Known attack pattern: reentrancy trigger
			return []byte{0xde, 0xad, 0xbe, 0xef}
		default:
			// Max-ish length
			b := make([]byte, 1024)
			rng.Read(b)
			return b
		}
	}
	size := rng.Intn(257) // 0–256 bytes
	b := make([]byte, size)
	rng.Read(b)
	return b
}

// --- bytes1–bytes32 (fixed) ---

func genFixedBytes(rng *rand.Rand, size int, boundary bool) interface{} {
	// go-ethereum ABI expects fixed byte arrays as [N]byte
	// We return a []byte of exactly `size` bytes and let the packer handle it.
	// Actually go-ethereum expects [N]byte as an array, so we use reflect via big allocation.
	// Simplest approach: return []byte of exact size; abi.Pack handles the conversion.
	// Note: go-ethereum abi.Pack needs [N]byte for fixedBytes, not []byte.
	// We build it via a switch on common sizes, or use a generic approach.
	b := make([]byte, size)
	if boundary {
		switch rng.Intn(3) {
		case 0:
			// all zeros — already zero
		case 1:
			for i := range b {
				b[i] = 0xff
			}
		default:
			rng.Read(b)
		}
	} else {
		rng.Read(b)
	}
	return fixedBytesValue(b, size)
}

// fixedBytesValue converts a []byte to the [N]byte array type go-ethereum expects.
func fixedBytesValue(b []byte, size int) interface{} {
	switch size {
	case 1:
		var a [1]byte
		copy(a[:], b)
		return a
	case 2:
		var a [2]byte
		copy(a[:], b)
		return a
	case 3:
		var a [3]byte
		copy(a[:], b)
		return a
	case 4:
		var a [4]byte
		copy(a[:], b)
		return a
	case 8:
		var a [8]byte
		copy(a[:], b)
		return a
	case 16:
		var a [16]byte
		copy(a[:], b)
		return a
	case 20:
		var a [20]byte
		copy(a[:], b)
		return a
	case 32:
		var a [32]byte
		copy(a[:], b)
		return a
	default:
		// For other sizes, use a map to cover all 1-32
		return fixedBytesFallback(b, size)
	}
}

func fixedBytesFallback(b []byte, size int) interface{} {
	// Cover remaining sizes not in the switch
	switch size {
	case 5:
		var a [5]byte
		copy(a[:], b)
		return a
	case 6:
		var a [6]byte
		copy(a[:], b)
		return a
	case 7:
		var a [7]byte
		copy(a[:], b)
		return a
	case 9:
		var a [9]byte
		copy(a[:], b)
		return a
	case 10:
		var a [10]byte
		copy(a[:], b)
		return a
	case 11:
		var a [11]byte
		copy(a[:], b)
		return a
	case 12:
		var a [12]byte
		copy(a[:], b)
		return a
	case 13:
		var a [13]byte
		copy(a[:], b)
		return a
	case 14:
		var a [14]byte
		copy(a[:], b)
		return a
	case 15:
		var a [15]byte
		copy(a[:], b)
		return a
	case 17:
		var a [17]byte
		copy(a[:], b)
		return a
	case 18:
		var a [18]byte
		copy(a[:], b)
		return a
	case 19:
		var a [19]byte
		copy(a[:], b)
		return a
	case 21:
		var a [21]byte
		copy(a[:], b)
		return a
	case 22:
		var a [22]byte
		copy(a[:], b)
		return a
	case 23:
		var a [23]byte
		copy(a[:], b)
		return a
	case 24:
		var a [24]byte
		copy(a[:], b)
		return a
	case 25:
		var a [25]byte
		copy(a[:], b)
		return a
	case 26:
		var a [26]byte
		copy(a[:], b)
		return a
	case 27:
		var a [27]byte
		copy(a[:], b)
		return a
	case 28:
		var a [28]byte
		copy(a[:], b)
		return a
	case 29:
		var a [29]byte
		copy(a[:], b)
		return a
	case 30:
		var a [30]byte
		copy(a[:], b)
		return a
	case 31:
		var a [31]byte
		copy(a[:], b)
		return a
	default:
		var a [32]byte
		copy(a[:], b)
		return a
	}
}

// --- dynamic arrays (slice) ---

func genSlice(rng *rand.Rand, t abi.Type, accounts []common.Address, boundary bool) (interface{}, error) {
	length := rng.Intn(5) // 0–4 elements for Phase 1
	if boundary && rng.Intn(2) == 0 {
		length = 0
	}

	// Build a typed slice via []interface{} for packing
	// go-ethereum abi.Pack handles typed slices; we must return the correct Go type.
	// For Phase 1 simplicity, build a []interface{} and pack manually.
	// Actually go-ethereum needs the concrete type. We use reflection-friendly approach:
	// For common types return concrete slices.
	if t.Elem == nil {
		return nil, fmt.Errorf("slice type has nil Elem")
	}

	switch t.Elem.T {
	case abi.UintTy:
		s := make([]*big.Int, length)
		for i := range s {
			s[i] = genUint(rng, t.Elem.Size, boundary)
		}
		return s, nil
	case abi.IntTy:
		s := make([]*big.Int, length)
		for i := range s {
			s[i] = genInt(rng, t.Elem.Size, boundary)
		}
		return s, nil
	case abi.AddressTy:
		s := make([]common.Address, length)
		for i := range s {
			s[i] = genAddress(rng, accounts, boundary)
		}
		return s, nil
	case abi.BoolTy:
		s := make([]bool, length)
		for i := range s {
			s[i] = rng.Intn(2) == 0
		}
		return s, nil
	case abi.BytesTy:
		s := make([][]byte, length)
		for i := range s {
			s[i] = genBytes(rng, boundary)
		}
		return s, nil
	default:
		// Fallback: return empty slice for unsupported element types
		return []interface{}{}, nil
	}
}

// --- fixed arrays ---

func genArray(rng *rand.Rand, t abi.Type, accounts []common.Address, boundary bool) (interface{}, error) {
	if t.Elem == nil {
		return nil, fmt.Errorf("array type has nil Elem")
	}
	// For fixed arrays, go-ethereum ABI needs [N]T arrays.
	// Return a []interface{} slice of the right length; go-ethereum Pack handles it.
	length := t.Size

	switch t.Elem.T {
	case abi.UintTy:
		s := make([]*big.Int, length)
		for i := range s {
			s[i] = genUint(rng, t.Elem.Size, boundary)
		}
		return s, nil
	case abi.AddressTy:
		s := make([]common.Address, length)
		for i := range s {
			s[i] = genAddress(rng, accounts, boundary)
		}
		return s, nil
	default:
		s := make([]interface{}, length)
		for i := range s {
			v, err := generateValue(rng, *t.Elem, accounts, boundary)
			if err != nil {
				return nil, err
			}
			s[i] = v
		}
		return s, nil
	}
}

// --- tuples (structs) ---

func genTuple(rng *rand.Rand, t abi.Type, accounts []common.Address, boundary bool) (interface{}, error) {
	fields := make([]interface{}, len(t.TupleElems))
	for i, elem := range t.TupleElems {
		v, err := generateValue(rng, *elem, accounts, boundary)
		if err != nil {
			return nil, fmt.Errorf("tuple field %d: %w", i, err)
		}
		fields[i] = v
	}
	return fields, nil
}
