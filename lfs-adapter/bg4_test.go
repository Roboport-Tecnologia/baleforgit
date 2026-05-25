package main

import (
	"bytes"
	"testing"
)

// bg4Split is the inverse, used only by these tests to round-trip.
func bg4Split(data []byte) []byte {
	n := len(data)
	split := n / 4
	rem := n % 4
	lens := [4]int{split, split, split, split}
	for i := 0; i < rem; i++ {
		lens[i]++
	}
	out := make([]byte, 0, n)
	for s := 0; s < 4; s++ {
		for i := 0; i < lens[s]; i++ {
			out = append(out, data[4*i+s])
		}
	}
	return out
}

func TestBg4RoundTrip(t *testing.T) {
	cases := [][]byte{
		nil,
		{1},
		{1, 2},
		{1, 2, 3},
		{1, 2, 3, 4},
		{1, 2, 3, 4, 5},
		{1, 2, 3, 4, 5, 6, 7},
		make([]byte, 0),
	}
	for i, c := range cases {
		got := bg4Regroup(bg4Split(c))
		if c == nil {
			if got != nil {
				t.Errorf("case %d (nil): expected nil, got %v", i, got)
			}
			continue
		}
		if !bytes.Equal(got, c) {
			t.Errorf("case %d: round-trip mismatch\n got: %v\nwant: %v", i, got, c)
		}
	}

	// Larger deterministic payload.
	big := make([]byte, 1023)
	for i := range big {
		big[i] = byte(i * 7)
	}
	if !bytes.Equal(bg4Regroup(bg4Split(big)), big) {
		t.Fatalf("large round-trip mismatch")
	}
}

func TestBg4MatchesXetCoreLayout(t *testing.T) {
	// For n=7 the spec says s0=2, s1=2, s2=2, s3=1.
	// Original: [a, b, c, d, e, f, g]
	// Split layout: [a, e, b, f, c, g, d]
	//   stream 0: [a, e]  (positions 0, 4)
	//   stream 1: [b, f]  (positions 1, 5)
	//   stream 2: [c, g]  (positions 2, 6)
	//   stream 3: [d]     (position 3)
	original := []byte{'a', 'b', 'c', 'd', 'e', 'f', 'g'}
	split := []byte{'a', 'e', 'b', 'f', 'c', 'g', 'd'}
	if !bytes.Equal(bg4Split(original), split) {
		t.Fatalf("bg4Split layout wrong: got %s", bg4Split(original))
	}
	if !bytes.Equal(bg4Regroup(split), original) {
		t.Fatalf("bg4Regroup wrong: got %s", bg4Regroup(split))
	}
}
