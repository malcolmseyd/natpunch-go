package antireplay

// thank you again to Wireguard-Go for helping me understand this
// most credit to https://git.zx2c4.com/wireguard-go/tree/replay/replay.go

// We use uintptr as blocks because pointers' size are optimized for the
// local CPU architecture.
const (
	// a word filled with 1's
	blockMask = ^uintptr(0)
	// each word is 2**blockSizeLog bytes long
	//             1 if > 8 bit     1 if > 16 bit     1 if > 32 bit
	blockSizeLog = blockMask>>8&1 + blockMask>>16&1 + blockMask>>32&1
	// size of word in bytes
	blockSize = 1 << blockSizeLog
)

const (
	// total number of bits in the array
	// must be power of 2
	blocksTotalBits = 1024
	// bits in a block
	blockBits = blockSize * 8
	// log of bits in a block
	blockBitsLog = blockSizeLog + 3
	// WindowSize is the size of the range in which indicies are stored
	// W = M-1*blockSize
	// uint64 to avoid casting in comparisons
	WindowSize = uint64(blocksTotalBits - blockBits)

	numBlocks = blocksTotalBits / blockSize
)

// Window is a sliding window that records which sequence numbers have been seen.
// It implements the anti-replay algorithm described in RFC 6479
type Window struct {
	highest uint64
	blocks  [numBlocks]uintptr
}

// Reset resets the window to its initial state
func (w *Window) Reset() {
	w.highest = 0
	// this is fine because higher blocks are cleared during Check()
	w.blocks[0] = 0
}

// Check records seeing index and returns true if the index is within the
// window and has not been seen before. If it returns false, the index is
// considered invalid.
func (w *Window) Check(index uint64) bool {
	// check if too old
	if index+WindowSize < w.highest {
		return false
	}

	// bits outside the block size represent which block the index is in
	indexBlock := index >> blockBitsLog

	// move window if new index is higher
	if index > w.highest {
		currTopBlock := w.highest >> blockBitsLog
		// how many blocks ahead is indexBlock?
		// cap it at a full circle around the array, at that point we clear the
		// whole thing
		newBlocks := min(indexBlock-currTopBlock, numBlocks)
		// clear each new block
		for i := uint64(1); i <= newBlocks; i++ {
			// mod index so it wraps around
			w.blocks[(currTopBlock+i)%numBlocks] = 0
		}
		w.highest = index
	}

	// we didn't mod until now because we needed to know the difference between
	// a lower index and wrapped higher index
	// we need to keep the index inside the array now
	indexBlock %= numBlocks

	// bits inside the block represent where in the block the bit is
	// mask it with the block size
	indexBit := index & uint64(blockBits-1)

	// finally check the index

	// save existing block to see if it changes
	oldBlock := w.blocks[indexBlock]
	// create updated block
	newBlock := oldBlock | (1 << indexBit)
	// set block to new value
	w.blocks[indexBlock] = newBlock

	// if the bit wasn't already 1, the values should be different and this should return true
	return oldBlock != newBlock
}

func min(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}
