package v4

import (
	"bytes"
	"context"
	"testing"

	"github.com/cubbit/dittofs/internal/adapter/adaptertest"
	"github.com/cubbit/dittofs/internal/adapter/adaptertest/nfsharness"
	"github.com/cubbit/dittofs/internal/adapter/core"
	"github.com/cubbit/dittofs/internal/adapter/nfs/protocol"
	"github.com/cubbit/dittofs/internal/prof"
	"github.com/cubbit/dittofs/pkg/resources"
	"github.com/cubbit/dittofs/pkg/vfs"
)

// The statuses SEQUENCE answers (RFC 8881 section 15.1) and the operation's code
// (section 18.46), written out so no test reads them back from the code.
const (
	statusBadSession   = 10052
	statusBadSlot      = 10053
	statusConnNotBound = 10055
	statusSequencePos  = 10064
	statusNotInSession = 10071
	statusFalseRetry   = 10076
	sequenceOKLen      = 44 // head 8, session 16, five words
	manySlots          = 8
)

// seqNode is a node holding one session, bound to the connection it was made
// on, whose SEQUENCE the tests run from other connections.
type seqNode struct {
	*node
	sess    *protocol.Session
	pool    *resources.Budget
	call    vfs.Call
	foreign *resources.Buf // the buffer of a request that is not the one under test
}

// newSeqNode confirms a client and makes its session of slots fore slots: under
// SP4_MACH_CRED when protect is set.
func newSeqNode(t *testing.T, slots uint32, protect bool) *seqNode {
	t.Helper()

	rn := adaptertest.NewRunner(t)
	n := newNode(t, rn, 7)
	s := &seqNode{node: n, pool: n.withPool(1 << 24), foreign: new(resources.Buf)}

	var cl vfs.ClientID

	var seq uint32

	if protect {
		s.call = protected(rn, vfs.ProtectionIntegrity)
		got := n.do(t, s.call, args("c1", verifier2, 0, spMach([]uint32{0}, []uint32{0})))
		wantStatus(t, got, statusOK)

		cl, seq = clientID(got), field(got, offSeq)
	} else {
		s.call = plain(rn)
		cl, seq = n.propose(t, s.call, "c1")
	}

	a := plainAsk(cl, seq)
	a.fore = chanArgs(1<<20, 1<<20, 4096, 8, slots)

	got := n.createOn(t, request(s.call, new(protocol.Bound)), a, builds)
	wantCreated(t, got)

	sess, ok := n.sessions.Get(sessionOf(got))
	if !ok {
		t.Fatal("the registry does not hold the session just made")
	}

	s.sess = sess

	return s
}

// sequence is SEQUENCE4args: the session, the sequence ID, the slot, the
// highest slot and sa_cachethis.
func sequence(id protocol.SessionID, seq, slot, highest uint32, cache bool) []byte {
	c := uint32(0)
	if cache {
		c = 1
	}

	return append(append([]byte(nil), id[:]...), words(seq, slot, highest, c)...)
}

// seqRequest is a request on the connection whose list is b, as Route builds it
// for a call whose first operation is SEQUENCE under key, holding owner.
func (s *seqNode) seqRequest(b *protocol.Bound, key uint64, owner *resources.Buf) *core.Request {
	r := request(s.call, b)
	r.Level = core.NeedsNegotiated

	st := r.State.(*protocol.State)
	st.SeqFirst, st.SeqKey, st.SeqOwner = true, key, owner

	return r
}

// run runs SEQUENCE with a over r.
func (s *seqNode) run(t *testing.T, r *core.Request, a []byte) []byte {
	t.Helper()

	return nfsharness.Member(t, s.rn, s.members, opSequence, r, a, refuse)
}

// head is SEQUENCE's result head, its code and the status.
func head(status uint32) []byte { return words(opSequence, status) }

// Every refusal SEQUENCE makes answers its status as the result, 8 bytes, and
// leaves the slot as it was: the next sequence ID on that slot still runs. A
// refusal that left the slot advanced, or stuck busy, would turn a client's
// retry into a lost request or a lost slot (RFC 8881 section 2.10.6.1.3).
func TestSequenceAnswersItsRefusalsAsItsResult(t *testing.T) {
	const key = 1

	type refusal struct {
		name    string
		protect bool
		setup   func(s *seqNode, b *protocol.Bound, owner *resources.Buf)
		args    func(s *seqNode) []byte
		first   bool // false: SEQUENCE is not the compound's first operation
		status  uint32
	}

	cases := []refusal{
		{
			name:   "a sequence ID that is not the next",
			args:   func(s *seqNode) []byte { return sequence(s.sess.ID, 5, 0, 0, false) },
			first:  true,
			status: 10063,
		},
		{
			name:   "a slot past the table",
			args:   func(s *seqNode) []byte { return sequence(s.sess.ID, 1, manySlots, 0, false) },
			first:  true,
			status: statusBadSlot,
		},
		{
			name: "a session this node does not hold",
			args: func(s *seqNode) []byte {
				return sequence(protocol.SessionID{9}, 1, 0, 0, false)
			},
			first:  true,
			status: statusBadSession,
		},
		{
			name: "a slot with a request in flight",
			setup: func(s *seqNode, _ *protocol.Bound, _ *resources.Buf) {
				s.sess.Begin(0, 1, key, s.foreign)
			},
			args:   func(s *seqNode) []byte { return sequence(s.sess.ID, 1, 0, 0, false) },
			first:  true,
			status: statusDelay,
		},
		{
			name: "the last request under another caller",
			setup: func(s *seqNode, _ *protocol.Bound, _ *resources.Buf) {
				s.sess.Begin(0, 1, 2, s.foreign)
				s.sess.Commit(0, s.foreign, []byte("kept"), true)
				s.sess.Release(0, s.foreign)
			},
			args:   func(s *seqNode) []byte { return sequence(s.sess.ID, 1, 0, 0, true) },
			first:  true,
			status: statusFalseRetry,
		},
		{
			name:   "an operation that is not the first",
			args:   func(s *seqNode) []byte { return sequence(s.sess.ID, 1, 0, 0, false) },
			status: statusSequencePos,
		},
		{
			name:    "a connection that is not bound, under a machine credential",
			protect: true,
			args:    func(s *seqNode) []byte { return sequence(s.sess.ID, 1, 0, 0, false) },
			first:   true,
			status:  statusConnNotBound,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newSeqNode(t, 1, c.protect)
			b := new(protocol.Bound)
			owner := new(resources.Buf)

			if c.setup != nil {
				c.setup(s, b, owner)
			}

			r := s.seqRequest(b, key, owner)
			r.State.(*protocol.State).SeqFirst = c.first

			if got := s.run(t, r, c.args(s)); !bytes.Equal(got, head(c.status)) {
				t.Errorf("SEQUENCE answered %x, want %x", got, head(c.status))
			}

			if r.Level >= core.NeedsSession {
				t.Errorf(
					"the refused SEQUENCE raised the request to level %d, want it left",
					r.Level,
				)
			}

			if c.protect && len(b.IDs()) != 0 {
				t.Errorf("the connection is bound to %x, want none", b.IDs())
			}
		})
	}
}

// A SEQUENCE that is allowed answers its session, sequence ID and slot as the
// client sent them and both highest slot IDs as the grant: whatever the client
// says is its highest slot in use, with a request in flight on slot 5 or none,
// it is not read as a retirement, so neither value moves and the pool's charge
// stays (RFC 8881 section 18.46.3; RFC 21 section 3.1).
func TestSequenceAnswersTheGrantAsItsHighestSlot(t *testing.T) {
	const (
		key  = 1
		slot = 3 // the slot ID is the client's: the result echoes it (RFC 8881 section 18.46.3)
	)

	for _, c := range []struct {
		name    string
		highest uint32
		busy    bool
	}{{"idle", 0, false}, {"slot 5 in flight", 5, true}} {
		t.Run(c.name, func(t *testing.T) {
			s := newSeqNode(t, manySlots, false)
			owner := new(resources.Buf)
			charged := s.pool.Reserved()

			if c.busy {
				s.sess.Begin(5, 1, key, s.foreign)
			}

			if got := s.sess.Begin(slot, 1, key, owner); got != protocol.SlotNew {
				t.Fatalf("Begin says %d, want new", got)
			}

			r := s.seqRequest(new(protocol.Bound), key, owner)
			got := s.run(t, r, sequence(s.sess.ID, 1, slot, c.highest, false))

			want := append(head(statusOK), s.sess.ID[:]...)
			want = append(want, words(1, slot, manySlots-1, manySlots-1, 0)...)

			if !bytes.Equal(got, want) {
				t.Errorf("SEQUENCE answered %x, want %x", got, want)
			}

			if s.pool.Reserved() != charged {
				t.Errorf("the pool holds %d bytes, want the %d it held", s.pool.Reserved(), charged)
			}

			if r.Level < core.NeedsSession {
				t.Errorf("the request is at level %d, want the session's", r.Level)
			}
		})
	}
}

// The retry of a request whose reply was not kept is answered SEQUENCE's own
// results with status NFS4_OK, not RETRY_UNCACHED_REP: the status is the next
// member's (RFC 8881 section 2.10.6.1.3, 18.46.3). The request is told it is
// that retry, so the members after it refuse, and it takes no mark, so the
// slot is left as the first request left it.
func TestSequenceAnswersTheRetryOfAnUncachedRequestOK(t *testing.T) {
	const key = 1

	s := newSeqNode(t, 1, false)
	s.sess.Begin(0, 1, key, s.foreign)
	s.sess.Commit(0, s.foreign, []byte("kept"), false)
	s.sess.Release(0, s.foreign)

	owner := new(resources.Buf)
	r := s.seqRequest(new(protocol.Bound), key, owner)

	got := s.run(t, r, sequence(s.sess.ID, 1, 0, 0, false))

	want := append(head(statusOK), s.sess.ID[:]...)
	want = append(want, words(1, 0, 0, 0, 0)...)

	if !bytes.Equal(got, want) {
		t.Errorf("SEQUENCE answered %x, want %x", got, want)
	}

	if !r.State.(*protocol.State).Uncached {
		t.Error("the request is not told it is the retry of an uncached one")
	}

	if r.Level < core.NeedsSession {
		t.Errorf("the request is at level %d, want the session's", r.Level)
	}

	if got := s.sess.Check(0, 1, key, nil); got != protocol.SlotUncached {
		t.Errorf("the slot says %v, want the uncached retry it said", got)
	}

	if s.sess.Commit(0, owner, nil, false) {
		t.Error("the retry committed into the slot, want it held no mark")
	}
}

// A SEQUENCE on a connection the session is not bound to binds it to the fore
// channel when the client's record is not SP4_MACH_CRED, and lists the session
// on it; the session is listed once however many SEQUENCEs follow (RFC 8881
// section 2.10.3.1).
func TestSequenceBindsAnUnboundConnection(t *testing.T) {
	const key = 1

	s := newSeqNode(t, 1, false)
	b := new(protocol.Bound)

	for seq := uint32(1); seq <= 2; seq++ {
		owner := new(resources.Buf)
		s.sess.Begin(0, seq, key, owner)

		got := s.run(t, s.seqRequest(b, key, owner), sequence(s.sess.ID, seq, 0, 0, false))
		if len(got) != sequenceOKLen {
			t.Fatalf("SEQUENCE %d answered %x, want %d bytes", seq, got, sequenceOKLen)
		}

		s.sess.Commit(0, owner, nil, false)
		s.sess.Release(0, owner)
	}

	if ids := b.IDs(); len(ids) != 1 || ids[0] != s.sess.ID {
		t.Errorf("the connection is bound to %x, want the session once", ids)
	}
}

// Under SP4_MACH_CRED a SEQUENCE on a connection the session is not bound to is
// refused, and binds nothing: the client binds it with BIND_CONN_TO_SESSION
// first (RFC 8881 section 2.10.3.1). The refusal leaves the slot as it was,
// the request's mark freed and committing nothing, so the sequence ID the client
// resends on the connection it then binds is the slot's next and runs (RFC 8881
// section 2.10.6.1.2).
func TestSequenceRefusesAnUnboundConnectionUnderMachCred(t *testing.T) {
	const key = 1

	s := newSeqNode(t, 1, true)
	b := new(protocol.Bound)
	owner := new(resources.Buf)
	s.sess.Begin(0, 1, key, owner)

	got := s.run(t, s.seqRequest(b, key, owner), sequence(s.sess.ID, 1, 0, 0, false))
	if !bytes.Equal(got, head(statusConnNotBound)) {
		t.Errorf("SEQUENCE answered %x, want %x", got, head(statusConnNotBound))
	}

	if ids := b.IDs(); len(ids) != 0 {
		t.Errorf("the connection is bound to %x, want none", ids)
	}

	if s.sess.Commit(0, owner, nil, false) {
		t.Error("the refused request still holds its slot's mark, and its reply moves the slot")
	}

	if st := s.sess.Check(0, 1, key, nil); st != protocol.SlotNew {
		t.Fatalf("sequence 1 after the refusal is %v, want %v", st, protocol.SlotNew)
	}

	bound := new(protocol.Bound)
	if !s.sessions.Bind(s.sess, bound) {
		t.Fatal("the connection is not bound")
	}

	owner = new(resources.Buf)
	s.sess.Begin(0, 1, key, owner)

	got = s.run(t, s.seqRequest(bound, key, owner), sequence(s.sess.ID, 1, 0, 0, false))
	if len(got) != sequenceOKLen {
		t.Errorf("SEQUENCE 1 on the bound connection answered %x, want %d bytes",
			got, sequenceOKLen)
	}
}

// A request that does not hold its slot's mark does not run: another request's
// buffer holding it, a SEQUENCE that was not admitted answers NFS4ERR_DELAY and
// takes nothing.
func TestSequenceNeedsItsMark(t *testing.T) {
	const key = 1

	s := newSeqNode(t, 1, false)
	owner := new(resources.Buf)

	s.sess.Begin(0, 1, key, s.foreign)

	got := s.run(
		t,
		s.seqRequest(new(protocol.Bound), key, owner),
		sequence(s.sess.ID, 1, 0, 0, false),
	)
	if !bytes.Equal(got, head(statusDelay)) {
		t.Errorf("SEQUENCE answered %x, want %x", got, head(statusDelay))
	}
}

// A request that was refused its slot at Admit, because another request held
// the mark, takes no mark. When that other request ends without a commit and
// frees the slot, SEQUENCE must not run the request: it would commit nothing,
// so the client's next sequence ID would be out of order and its resend would
// run the compound a second time (RFC 8881 section 2.10.6.1).
func TestSequenceRefusesASlotFreedAfterItWasBusy(t *testing.T) {
	const key = 1

	s := newSeqNode(t, 1, false)
	owner := new(resources.Buf)

	if got := s.sess.Begin(0, 1, key, s.foreign); got != protocol.SlotNew {
		t.Fatalf("Begin for the first request = %v, want SlotNew", got)
	}

	if got := s.sess.Begin(0, 1, key, owner); got != protocol.SlotBusy {
		t.Fatalf("Begin for the resend = %v, want SlotBusy", got)
	}

	s.sess.Release(0, s.foreign)

	r := s.seqRequest(new(protocol.Bound), key, owner)

	got := s.run(t, r, sequence(s.sess.ID, 1, 0, 0, false))
	if !bytes.Equal(got, head(statusDelay)) {
		t.Errorf("SEQUENCE answered %x, want %x", got, head(statusDelay))
	}

	if r.Level&^core.NeedsFH >= core.NeedsSession {
		t.Error("the request holds no mark, yet SEQUENCE let it run")
	}
}

// SEQUENCE's row is cacheable: core hands the reply to the cache only when a
// member that ran has a cacheable row, and a SEQUENCE the cache never saw would
// leave its slot where it was, so the client's next sequence ID is out of order
// (RFC 21 section 3.1).
func TestTheSequenceRowIsCacheable(t *testing.T) {
	s := newSeqNode(t, 1, false)

	row := Table(s.h).Ops[1].Members.Ops[opSequence]
	if row == nil || !row.Cacheable {
		t.Fatalf("the row at %d is %+v, want a cacheable SEQUENCE", opSequence, row)
	}

	if row.Versions.First != 1 || row.Versions.Last != lastMinor {
		t.Errorf("the row serves %+v, want NFSv4.1 and later", row.Versions)
	}
}

// SEQUENCE's role is context: a node that is draining still serves a compound
// that opens with it, so a client can still release its state with CLOSE or
// DESTROY_SESSION; a row with no role has every NFSv4.1 compound refused with
// the drain's error (RFC 21 section 11.5).
func TestTheSequenceRowServesWhileDraining(t *testing.T) {
	s := newSeqNode(t, 1, false)

	row := Table(s.h).Ops[1].Members.Ops[opSequence]
	if row == nil || row.Role != core.RoleContext {
		t.Fatalf("the row at %d is %+v, want a SEQUENCE whose role is context", opSequence, row)
	}
}

// SEQUENCE is on every COMPOUND of NFSv4.1, so its member allocates only the
// result it returns, the arm of its reply; the slot check and the bind check
// allocate nothing (RFC 20 section 6.9).
//
// ponytail: the result arm is one allocation, where none would be ideal: the
// generated codec's arm is a pointer to a struct the member makes. Remove it
// when the codec takes an arm held in the request's state.
func TestTheSequenceMemberAllocatesOnlyItsResult(t *testing.T) {
	if prof.RaceEnabled {
		t.Skip("the allocation count says nothing under the detector")
	}

	const key = 1

	s := newSeqNode(t, 1, false)
	owner := new(resources.Buf)
	s.sess.Begin(0, 1, key, owner)

	r := s.seqRequest(new(protocol.Bound), key, owner)
	a := sequenceArgs{SessionID: s.sess.ID, SequenceID: 1}

	if n := testing.AllocsPerRun(200, func() {
		r.Level = core.NeedsNegotiated

		if _, err := s.h.Sequence(context.Background(), r, a); err != nil {
			t.Fatal(err)
		}
	}); n > 1 {
		t.Errorf("the SEQUENCE member allocates %v per call, want its result alone", n)
	}
}
