package protocol

import (
	"context"
	"encoding/binary"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/cubbit/dittofs/pkg/resources"
)

// slotConnections is the number of connections one session's requests come
// from: the cap of a connection's in-flight requests, each connection on a slot
// of its own.
const slotConnections = 64

// BenchmarkASessionUnderManyConnections measures the whole of a cached SEQUENCE
// request's path through the node's tables, from 64 goroutines on one session,
// each on its own slot and its own flow: the session lookup Route makes, the flow's admit, the
// replay lookup, the lookup the SEQUENCE member makes, the store and the
// release. What it loads are the two locks every connection takes, Sessions.Get's
// and the slot table's. Run it with -mutexprofile and -blockprofile to read
// each lock's wait: go test -run '^$' -bench ASessionUnder -mutexprofile m.out
// -blockprofile b.out ., then go tool pprof -top -sample_index=delay.
func BenchmarkASessionUnderManyConnections(b *testing.B) {
	s := newSlottedWith(b, slotConnections)
	ctx := context.Background()
	reply := &resources.Buf{B: replyOf(0x10, "reply")}

	// the call's sequence ID is the last word that differs between two calls
	// that differ in it alone.
	first, second := s.call(0x10, 1, 0, true, 1000), s.call(0x10, 2, 0, true, 1000)
	seqAt := -1

	for i := range first {
		if first[i] != second[i] {
			seqAt = i - 3
		}
	}

	if seqAt < 0 {
		b.Fatal("two calls with different sequence IDs do not differ")
	}

	var slots atomic.Uint32

	b.ReportAllocs()
	// RunParallel starts parallelism times GOMAXPROCS goroutines: one for each
	// connection and no more, since a slot belongs to one.
	b.SetParallelism(max(1, slotConnections/runtime.GOMAXPROCS(0)))
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		slot := slots.Add(1) - 1
		if slot >= slotConnections {
			return
		}

		// each connection has a flow of its own, as the server gives it.
		flow := NewFlow(s.reg)
		call := s.call(0x10, 1, slot, true, 1000)
		h := headOf(call)
		seq := uint32(0)

		for pb.Next() {
			seq++
			binary.BigEndian.PutUint32(call[seqAt:], seq)

			s.reg.Get(s.sess.ID)

			rel, err := flow.Admit(ctx, h)
			if err != nil {
				b.Errorf("Admit: %v", err)

				return
			}

			if buf, err := s.w.Lookup(ctx, h); buf != nil || err != nil {
				b.Errorf("a new request's lookup answers %v with %v, want a plain miss", err, buf)

				return
			}

			s.reg.Get(s.sess.ID)
			s.w.Store(h, reply)
			rel()
		}
	})
}
