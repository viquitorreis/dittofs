package core_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"github.com/cubbit/dittofs/internal/adapter/adaptertest"
	"github.com/cubbit/dittofs/internal/adapter/adaptertest/testproto"
	"github.com/cubbit/dittofs/internal/adapter/core"
	"github.com/cubbit/dittofs/pkg/adapter"
	"github.com/cubbit/dittofs/pkg/resources"
	"github.com/cubbit/dittofs/pkg/vfs"
)

// countedFlow tracks the requests whose place is held.
type countedFlow struct {
	core.FlowControl
	mu   sync.Mutex
	held map[core.Header]bool
}

func (f *countedFlow) Admit(ctx context.Context, h core.Header) (func(), error) {
	release, err := f.FlowControl.Admit(ctx, h)
	if err != nil {
		return nil, err
	}

	f.mu.Lock()
	f.held[h] = true
	f.mu.Unlock()

	return func() {
		f.mu.Lock()
		delete(f.held, h)
		f.mu.Unlock()
		release()
	}, nil
}

// places is how many requests' places are held.
func (f *countedFlow) places() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return len(f.held)
}

func (f *countedFlow) holds(h core.Header) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.held[h]
}

// orderedReplay counts the replies stored, and those stored after the place
// of their request was released, and keeps the bytes of the last one.
type orderedReplay struct {
	core.ReplayCache
	flow   *countedFlow
	stored atomic.Int32
	late   atomic.Int32
	mu     sync.Mutex
	last   []byte
}

func (o *orderedReplay) Store(h core.Header, reply *resources.Buf) {
	o.stored.Add(1)

	if !o.flow.holds(h) {
		o.late.Add(1)
	}

	o.mu.Lock()
	o.last = append(o.last[:0], reply.B...)
	o.mu.Unlock()

	o.ReplayCache.Store(h, reply)
}

// cacheableEcho is a Router declared in the test that makes the Echo row
// Cacheable, so a request alone is stored, which the protocol's one other
// Cacheable row, the Create, reaches only inside a chain.
type cacheableEcho struct {
	core.Router
	once sync.Once
}

func (r *cacheableEcho) Route(
	h core.Header, prev *core.Request,
) (*core.OpTable, *core.Request, error) {
	tb, req, err := r.Router.Route(h, prev)
	if err == nil {
		r.once.Do(func() { tb.Ops[testproto.OpEcho].Cacheable = true })
	}

	return tb, req, err
}

// ordered serves messages whose replies are stored through o, over a flow that
// counts the places held.
func ordered(t *testing.T, o *orderedReplay) *served {
	t.Helper()

	return newServedOn(t, 1<<20, adapter.Deps{}, func(p core.Protocol) core.Protocol {
		return edited{p, func(st *core.Stages) {
			o.flow = &countedFlow{FlowControl: core.NewCapped(), held: map[core.Header]bool{}}
			st.Flow = o.flow
			o.ReplayCache = st.Replay
			st.Replay = o
			st.Router = &cacheableEcho{Router: st.Router}
		}}
	})
}

// A reply is kept before its request's place is released, for a request alone
// and a compound: a retransmission that finds the place free then finds the
// reply, and is never run again (RFC 20 §4.7).
func TestAReplyIsKeptBeforeItsPlaceIsReleased(t *testing.T) {
	adaptertest.CheckLeaks(t, nil)

	o := &orderedReplay{}
	s := ordered(t, o)

	s.serve(s.fhThenCreate(1, "a")...)

	if st := s.statuses(); len(st) != 2 || st[1] != testproto.StatusOK {
		t.Fatalf("the chain's Create is answered %v", st)
	}

	s.serve(testproto.Msg{
		Op: testproto.OpEcho, Version: 1, ID: 5, Credits: 1, Payload: []byte("a"),
	})

	if r := s.read(); r.Status != testproto.StatusOK {
		t.Fatalf("the Echo is answered %+v", r)
	}

	s.compound(2,
		testproto.Msg{Op: testproto.OpPutFH, Handle: s.root},
		testproto.Msg{Op: testproto.OpCreate, Name: "b"},
	)

	if st, _ := s.results(); st != testproto.StatusOK {
		t.Fatalf("the compound's Create is answered %d", st)
	}

	if n := o.stored.Load(); n != 3 {
		t.Fatalf("%d replies stored, want the Create's, the Echo's and the compound's", n)
	}

	if n := o.late.Load(); n != 0 {
		t.Errorf("%d replies stored after their request's place was released, want none", n)
	}
}

// A compound the connection's close cancels after a member ran and answered is
// still encoded, into the reply it reserved, and kept for its retry, though no
// byte of it is sent: a retry on a new connection is then answered it, and
// never makes the file again (RFC 20 §6.5, §4.7). The Create is held until the
// close has cancelled the request, then answers whole.
func TestACompoundTheCloseCancelsAfterAMemberRanIsKeptUnsent(t *testing.T) {
	keptUnsent(t)
}

// The same, with a member after the Create that its table lacks: the cancelled
// compound is ended after the Create, the later member answered once, as the
// table maps a delay, and not again for the code it lacks.
func TestACancelledCompoundIsEndedBeforeAMemberItCannotDecode(t *testing.T) {
	keptUnsent(t, testproto.Msg{Op: 99})
}

// keptUnsent runs the compound of a PutFH, a Create and the members after them,
// with the close cancelling it once the Create answers, and checks it is kept
// whole and sent to no one.
func keptUnsent(t *testing.T, after ...testproto.Msg) {
	t.Helper()

	synctest.Test(t, func(t *testing.T) {
		o := &orderedReplay{}
		s := ordered(t, o)
		put := testproto.Msg{Op: testproto.OpPutFH, Handle: s.root}

		members := func(name string) []testproto.Msg {
			return append([]testproto.Msg{put, {Op: testproto.OpCreate, Name: name}}, after...)
		}

		s.compound(1, members("whole")...)

		if len(after) == 0 {
			if st, _ := s.results(); st != testproto.StatusOK {
				t.Fatalf("the compound's Create is answered %d", st)
			}
		} else {
			s.read() // the compound ends at the member its table lacks, answered an error
		}

		whole := append([]byte(nil), o.last...)
		hold := s.faults.Hold(vfs.OpCreate)

		s.compound(2, members("cut")...)
		<-hold.Reached()
		s.p.Close()
		hold.Release()

		if !s.sentNothing() {
			t.Fatal("a reply was sent on the connection the close cancelled")
		}

		if n := o.stored.Load(); n != 2 {
			t.Fatalf("%d replies stored, want the close-cancelled compound's too", n)
		}

		if s.creates() != 2 {
			t.Errorf("%d files made, want the two Creates that ran", s.creates())
		}

		if len(o.last) != len(whole) {
			t.Errorf("the kept reply is %d bytes, want the %d of the same compound answered whole",
				len(o.last), len(whole))
		}
	})
}

// A compound the close cancels at a member that failed, with a mapped refusal
// that is no fault, ends at that member: no result follows a failed member, so
// the reply kept for the retry is the one the same compound answers whole, and
// not one with a delay result added after the failure (RFC 8881 section
// 16.2.3). The Echo answers an I/O error, and is held until the close cancels
// the request.
func TestACompoundTheCloseCancelsAtAFailedMemberEndsThere(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		o := &orderedReplay{}
		reached, release := make(chan struct{}), make(chan struct{})
		armed := false

		s := newServedOn(t, 1<<20, adapter.Deps{}, func(p core.Protocol) core.Protocol {
			p = p.(*testproto.Protocol).WithEchoSeen(func([]byte) {
				if armed {
					close(reached)
					<-release
				}
			})

			return edited{p, func(st *core.Stages) {
				o.flow = &countedFlow{FlowControl: core.NewCapped(), held: map[core.Header]bool{}}
				st.Flow = o.flow
				o.ReplayCache = st.Replay
				st.Replay = o
				st.Router = &cacheableEcho{Router: st.Router}
			}}
		})
		members := func(name string) []testproto.Msg {
			return []testproto.Msg{
				{Op: testproto.OpPutFH, Handle: s.root},
				{Op: testproto.OpCreate, Name: name},
				{Op: testproto.OpEcho, Payload: []byte(testproto.JoinedIO)},
				{Op: testproto.OpCreate, Name: "after"},
			}
		}

		s.compound(1, members("one")...)

		if st, rs := s.results(); st != testproto.StatusIO || len(rs) != 3 {
			t.Fatalf("the failing compound is answered %d with %v, want three results", st, rs)
		}

		whole := append([]byte(nil), o.last...)
		armed = true

		s.compound(2, members("two")...)
		<-reached
		s.p.Close()
		close(release)

		if !s.sentNothing() {
			t.Fatal("a reply was sent on the connection the close cancelled")
		}

		if n := o.stored.Load(); n != 2 {
			t.Fatalf("%d replies stored, want both compounds'", n)
		}

		if len(o.last) != len(whole) {
			t.Errorf("the kept reply is %d bytes, want the %d of the same compound "+
				"ended at its failed member", len(o.last), len(whole))
		}
	})
}

// A drain that begins after a request's place was taken refuses a compound
// whose members it does not serve: the compound opens with a member whose role
// is context, as SEQUENCE's is, and a member after it whose role is none, so nothing
// runs, nothing is answered, nothing is stored and no place stays held; the
// retransmission is refused again. A compound of members the drain serves
// whole runs and keeps its reply (RFC 21 section 11.5, RFC 20 section 3.1).
func TestADrainBetweenAdmitAndItsMemberFreesThePlace(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		o := &orderedReplay{}
		s := ordered(t, o)
		put := testproto.Msg{Op: testproto.OpPutFH, Handle: s.root}
		context := testproto.Msg{Op: testproto.OpEcho, Role: core.RoleContext, Payload: []byte("a")}
		none := testproto.Msg{Op: testproto.OpEcho, Role: core.RoleNone, Payload: []byte("a")}

		s.p.Drain()
		s.compound(1, context, put, context)

		if st, rs := s.results(); st != testproto.StatusOK || len(rs) != 3 {
			t.Fatalf("the compound of context members is answered %d with %v, want all three run",
				st, rs)
		}

		if n := o.flow.places(); n != 0 {
			t.Errorf("%d places held after the served compound, want none", n)
		}

		stored := o.stored.Load()

		// the retransmission is the same compound again.
		for range 2 {
			s.compound(2, context, put,
				testproto.Msg{Op: testproto.OpCreate, Name: "drained"}, none)
		}

		if !s.sentNothing() {
			t.Error("a drained compound with a refused member, or its retransmission, was answered")
		}

		if n := s.creates(); n != 0 {
			t.Errorf("the drained compound made %d files, want none", n)
		}

		if n := o.flow.places(); n != 0 {
			t.Errorf("%d places held after the drain refused the compound twice, want none", n)
		}

		if n := o.stored.Load(); n != stored {
			t.Errorf("%d replies stored, want the %d before the drained compound", n, stored)
		}
	})
}
