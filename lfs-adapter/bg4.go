package main

// bg4Regroup reverses the ByteGrouping4 transform applied during xet-core's
// `ByteGrouping4LZ4` compression. Given the bytes `[s0 | s1 | s2 | s3]`
// (the LZ4-decompressed payload), it returns the original interleaved buffer
// where output[i] came from stream (i % 4) at position (i / 4) — with the
// nuance that any remainder bytes were appended to the lowest-indexed streams
// first.
//
// Stream sizing for total length n, split = n/4, rem = n%4:
//
//	len(s0) = split + (1 if rem>=1)
//	len(s1) = split + (1 if rem>=2)
//	len(s2) = split + (1 if rem>=3)
//	len(s3) = split
//
// Mirrors `bg4_regroup_together` in
// xet_core_structures/src/xorb_object/byte_grouping/bg4.rs.
func bg4Regroup(g []byte) []byte {
	n := len(g)
	if n == 0 {
		return nil
	}
	split := n / 4
	rem := n % 4

	lens := [4]int{split, split, split, split}
	for i := 0; i < rem; i++ {
		lens[i]++
	}
	// Offsets where each stream begins inside g.
	starts := [4]int{0, lens[0], lens[0] + lens[1], lens[0] + lens[1] + lens[2]}

	out := make([]byte, n)
	// First 4*split bytes are pure interleaving.
	for i := 0; i < split; i++ {
		out[4*i+0] = g[starts[0]+i]
		out[4*i+1] = g[starts[1]+i]
		out[4*i+2] = g[starts[2]+i]
		out[4*i+3] = g[starts[3]+i]
	}
	// Tail: up to 3 leftover bytes pulled from s0[split], s1[split], s2[split].
	tail := 4 * split
	for j := 0; j < rem; j++ {
		out[tail+j] = g[starts[j]+split]
	}
	return out
}
