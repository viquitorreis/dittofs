package nfs

import (
	"context"
	"flag"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cubbit/dittofs/internal/adapter/adaptertest/nfsclient"
	"github.com/cubbit/dittofs/pkg/resources"
)

// replayConns is the number of connections a busy adapter's replay cache is
// measured under: all of them reach the one cache.
const replayConns = 64

// replayCalls is the number of calls each connection sends. The default keeps
// the test in the normal run; a profile run raises it, as
//
//	go test -run TestReplayUnder64Connections -mutexprofile m.out \
//	  -blockprofile b.out ./internal/adapter/nfs/ -replaycalls 300
//
// The cache keeps each reply, about 540 bytes a call with its map entry and
// the service's record, and the leak check's heap slack is 16 MiB, so the
// count stays under about 400 for each of the 64 connections.
var replayCalls = flag.Int(
	"replaycalls",
	20,
	"calls each of the 64 connections sends (at most about 400)",
)

// 64 connections send calls of their own at once, every call a miss of the
// replay cache: the service serves exactly one Create for each, and every
// reply is its own call's. The cache keys a call by its client address and its
// xid, so one xid shared by two connections of the one address would be one
// call whose reply the other is answered from the cache, with no Create run.
// The test logs how long the load lasted: with -mutexprofile and
// -blockprofile it is the time the cache's lock wait is measured against.
func TestReplayUnder64Connections(t *testing.T) {
	calls := *replayCalls

	// The connection budget leakChecked gives holds 16 connections of
	// 64 KiB each; this one holds the 64 the test opens.
	mem, _, srv := replaying(t, allVersions, func(s *replayShape) {
		s.d.Budgets.Connection = resources.NewBudget("connection", 8<<20)
	})
	addr := serving(t, srv)

	conns := make([]*nfsclient.Client, replayConns)
	for i := range conns {
		conns[i] = client(t, addr)
	}

	var (
		xid  atomic.Uint32
		gate = make(chan struct{})
		wg   sync.WaitGroup
	)

	for _, c := range conns {
		wg.Add(1)

		go func() {
			defer wg.Done()

			<-gate

			for range calls {
				x := xid.Add(1)
				call := nfsclient.Call{XID: &x, Prog: progNFS, Vers: 3, Proc: 0}

				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				reply, err := c.Do(ctx, call)

				cancel()

				if err != nil {
					t.Errorf("call %d: %v", x, err)

					return
				}

				if reply.Denied || reply.Stat != 0 || reply.XID != x {
					t.Errorf("call %d was answered %+v, want its own success", x, reply)

					return
				}
			}
		}()
	}

	start := time.Now()

	close(gate)
	wg.Wait()

	t.Logf("load phase: %d calls in %v", replayConns*calls, time.Since(start))

	wantCreates(t, "64 connections", mem, replayConns*calls)
}
