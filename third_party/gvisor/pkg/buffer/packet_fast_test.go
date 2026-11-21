// SPDX-License-Identifier: Apache-2.0

package buffer

import (
	"bytes"
	"testing"
)

func TestPullUpSliceAcrossViewsAndClones(t *testing.T) {
	b := MakeWithData([]byte("12abc"))
	defer b.Release()
	b.TrimFront(2)
	tail := MakeWithData([]byte("def"))
	b.Merge(&tail)

	data, ok := b.PullUpSlice(1, 2)
	if !ok || string(data) != "bc" {
		t.Fatalf("first view = %q, %v", data, ok)
	}
	data[0] = 'B'
	clone := b.Clone()
	defer clone.Release()
	for _, tc := range []struct {
		start, length int
		want          string
	}{{0, 1, "a"}, {2, 2, "cd"}, {5, 1, "f"}} {
		data, ok := clone.PullUpSlice(tc.start, tc.length)
		if !ok || string(data) != tc.want {
			t.Fatalf("range %d+%d = %q, %v", tc.start, tc.length, data, ok)
		}
		data[0] = 'X'
	}
	if got := string(b.Flatten()); got != "aBcdef" {
		t.Fatalf("original after writes to clone = %q", got)
	}
	if _, ok := b.PullUpSlice(5, 2); ok {
		t.Fatal("accepted range beyond end")
	}
	if data, ok := b.PullUpSlice(0, 0); !ok || data != nil {
		t.Fatalf("empty range = %v, %v", data, ok)
	}
}

func TestNewViewWithDataInitializesSpareCapacity(t *testing.T) {
	for _, size := range []int{0, 63, 64, 65, 1200, MaxChunkSize + 1} {
		src := bytes.Repeat([]byte{0xff}, size)
		v := NewViewWithData(src)
		if !bytes.Equal(v.AsSlice(), src) {
			t.Fatalf("size %d: payload mismatch", size)
		}
		for _, b := range v.chunk.data[size:] {
			if b != 0 {
				t.Fatalf("size %d: stale data in spare capacity", size)
			}
		}
		for i := range v.chunk.data {
			v.chunk.data[i] = 0x55
		}
		v.Release()
	}
}
