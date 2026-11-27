package protocol

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/cubbit/dittofs/internal/adapter/core"
	"github.com/cubbit/dittofs/internal/adapter/nfs/wire"
	"github.com/cubbit/dittofs/internal/prof"
	"github.com/cubbit/dittofs/pkg/adapter/settings"
	"github.com/cubbit/dittofs/pkg/resources"
	"github.com/cubbit/dittofs/pkg/vfs"
)

// slotted is a node with one session of fore slots caching 64 bytes a reply,
// the replay stage and the flow that serve its calls.
type slotted struct {
	reg  *Sessions
	sess *Session
	w    *replayStage
	f    *Flow
	t    testing.TB
}

func newSlotted(t *testing.T) *slotted { return newSlottedWith(t, 4) }

// newSlottedWith is a node whose one session has slots fore slots.
func newSlottedWith(t testing.TB, slots uint32) *slotted {
	t.Helper()

	b := &resources.Budgets{Connection: resources.NewBudget("slots", 1<<20)}
	reg := NewSessions(b, &fakeClock{}, rand.Reader)

	sess, err := reg.Create(
		1,
		Spec{
			Fore: Channel{
				Slots: slots, MaxRequest: 1024, MaxResponse: 1024, MaxCached: 64, MaxOps: 8,
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	w, _ := replayed(1 << 20)
	w.sessions = reg
	w.served = newServed(
		settings.VersionRange{Min: "4.1", Max: "4.1"},
		Tables{V4: core.NewOpTable(w.errs, false)},
	)

	return &slotted{reg: reg, sess: sess, w: w, f: NewFlow(reg), t: t}
}

// call is a minor version 1 COMPOUND on the session whose first operation is
// SEQUENCE at slot and seq, under AUTH_SYS of uid and gids.
func (s *slotted) call(xid, seq, slot uint32, cache bool, uid uint32, gids ...uint32) []byte {
	u := binary.BigEndian.AppendUint32
	args := u(u(u(nil, 0), 1), 1) // tag "", minor 1, one operation
	args = u(args, wire.OpSequence)
	args = append(args, s.sess.ID[:]...)

	args = u(u(u(args, seq), slot), 0)
	if cache {
		args = u(args, 1)
	} else {
		args = u(args, 0)
	}

	b := nullCall(wire.ProgNFS, wire.VersNFS4, wire.ProcCompound, wire.AuthSys,
		authSys("h", uid, 100, gids...), wire.AuthNone, nil, args)
	binary.BigEndian.PutUint32(b, xid)

	return b
}

// gssHeader is a header the way the RPCSEC_GSS unwrap will set it: with the
// principal and service its call was protected under.
type gssHeader struct {
	header
	principal string
	service   uint32
}

func (g gssHeader) gssIdentity() (string, uint32) { return g.principal, g.service }

// admit runs a call through the flow: its header, and the release it returns.
func (s *slotted) admit(b []byte) (core.Header, func()) {
	s.t.Helper()

	h := headOf(b)

	rel, err := s.f.Admit(context.Background(), h)
	if err != nil {
		s.t.Fatal(err)
	}

	return h, rel
}

// hit is what the replay stage answers h, nil for none.
func (s *slotted) hit(h core.Header) []byte {
	s.t.Helper()

	buf, err := s.w.Lookup(context.Background(), h)
	if err != nil {
		s.t.Fatalf("Lookup: %v", err)
	}

	if buf == nil {
		return nil
	}
	defer buf.Release()

	return bytes.Clone(buf.B)
}

// replyOf is a reply that begins with xid.
func replyOf(xid uint32, body string) []byte {
	return append(binary.BigEndian.AppendUint32(nil, xid), body...)
}

// A cached request resent on another connection, under a new transaction ID,
// is answered its first reply with that ID (RFC 8881 section 2.10.6.1.3).
func TestACachedRequestIsAnsweredFromItsSlot(t *testing.T) {
	s := newSlotted(t)

	h, rel := s.admit(s.call(0x10, 1, 2, true, 1000))
	if got := s.hit(h); got != nil {
		t.Fatalf("a new request is answered %x from the cache", got)
	}

	s.w.Store(h, &resources.Buf{B: replyOf(0x10, "first")})
	rel()

	got := s.hit(headOf(s.call(0x77, 1, 2, true, 1000)))
	if want := replyOf(0x77, "first"); !bytes.Equal(got, want) {
		t.Errorf("the resend is answered %x, want %x", got, want)
	}
}

// Without cachethis the reply is not kept: the resend is no hit, and the slot
// names it uncached (RFC 8881 section 2.10.6.1.3.1).
func TestAnUncachedRequestIsNotAnswered(t *testing.T) {
	s := newSlotted(t)
	h, rel := s.admit(s.call(0x10, 1, 0, false, 1000))
	s.w.Store(h, &resources.Buf{B: replyOf(0x10, "first")})
	rel()

	again := headOf(s.call(0x10, 1, 0, false, 1000))
	if got := s.hit(again); got != nil {
		t.Errorf("an uncached reply is answered: %x", got)
	}

	if st := s.sess.Check(0, 1, s.keyOf(again), nil); st != SlotUncached {
		t.Errorf("the resend of an uncached request is %v, want %v", st, SlotUncached)
	}

	next := headOf(s.call(0x11, 2, 0, false, 1000))
	if st := s.sess.Check(0, 2, s.keyOf(next), nil); st != SlotNew {
		t.Errorf("the next sequence after an uncached request is %v, want %v", st, SlotNew)
	}
}

func (s *slotted) keyOf(h core.Header) uint64 { return callerKey(h) }

// A slot is in flight from its Admit to its Store: a resend meanwhile is busy
// and answered nothing, and once the first's Store ran it is the first's reply.
func TestASlotIsBusyBetweenAdmitAndStore(t *testing.T) {
	s := newSlotted(t)
	first, rel := s.admit(s.call(0x10, 1, 3, true, 1000))
	resend := headOf(s.call(0x10, 1, 3, true, 1000))

	if got := s.hit(resend); got != nil {
		t.Errorf("a resend of a request still running is answered %x", got)
	}

	if st := s.sess.Check(3, 1, s.keyOf(resend), resend.(header).rec); st != SlotBusy {
		t.Errorf("the resend meanwhile is %v, want %v", st, SlotBusy)
	}

	// The resend commits nothing, though it reaches Store like any request.
	s.w.Store(first, &resources.Buf{B: replyOf(0x10, "first")})
	s.w.Store(resend, &resources.Buf{B: replyOf(0x10, "second")})
	rel()

	got, want := s.hit(headOf(s.call(0x10, 1, 3, true, 1000))), replyOf(0x10, "first")
	if !bytes.Equal(got, want) {
		t.Errorf("a later resend is answered %q, want %q", got, want)
	}
}

// Only the request Begin marked holds its slot's mark: another caller, none,
// a slot past the table and the marked request after its release hold nothing.
func TestOnlyTheMarkedRequestHoldsItsSlot(t *testing.T) {
	s := newSlotted(t)
	owner, other := new(resources.Buf), new(resources.Buf)

	if got := s.sess.Begin(1, 1, 7, owner); got != SlotNew {
		t.Fatalf("Begin = %v, want %v", got, SlotNew)
	}

	for _, tc := range []struct {
		name string
		id   uint32
		by   *resources.Buf
		want bool
	}{
		{"the marked request", 1, owner, true},
		{"another caller", 1, other, false},
		{"no owner", 1, nil, false},
		{"a free slot", 2, owner, false},
		{"a slot past the table", 99, owner, false},
	} {
		if got := s.sess.HoldsMark(tc.id, tc.by); got != tc.want {
			t.Errorf("%s: HoldsMark = %v, want %v", tc.name, got, tc.want)
		}
	}

	s.sess.Release(1, owner)

	if s.sess.HoldsMark(1, owner) {
		t.Error("the released request still holds the mark")
	}
}

// A request a drain refused after its admission leaves its slot as it was: its
// release frees the slot, and its retransmission is a new request again.
func TestAReleaseWithoutStoreFreesTheSlot(t *testing.T) {
	s := newSlotted(t)

	h, rel := s.admit(s.call(0x10, 1, 1, true, 1000))
	if st := s.sess.Check(1, 1, s.keyOf(h), nil); st != SlotBusy {
		t.Fatalf("an admitted request's slot is %v, want %v", st, SlotBusy)
	}

	rel()

	if st := s.sess.Check(1, 1, s.keyOf(h), nil); st != SlotNew {
		t.Errorf("after the release the retransmission is %v, want %v", st, SlotNew)
	}
}

// Under SP4_MACH_CRED a cached reply is answered to the connection the session
// is bound to alone: on another, the lookup answers nothing, so the SEQUENCE
// member refuses it as not bound, and the slot's reply stays for the bound
// connection (RFC 8881 section 18.46.3).
func TestACachedReplyIsNotAnsweredOnAnUnboundConnectionUnderMachCred(t *testing.T) {
	s := newSlotted(t)
	s.sess.Protect = true
	s.w.bound = new(Bound)

	h, rel := s.admit(s.call(0x10, 1, 0, true, 1000))
	s.w.Store(h, &resources.Buf{B: replyOf(0x10, "first")})
	rel()

	resend := headOf(s.call(0x11, 1, 0, true, 1000))
	if got := s.hit(resend); got != nil {
		t.Errorf("a resend on an unbound connection is answered %q, want nothing", got)
	}

	if !s.reg.Bind(s.sess, s.w.bound) {
		t.Fatal("the connection is not bound")
	}

	if got, want := s.hit(resend), replyOf(0x11, "first"); !bytes.Equal(got, want) {
		t.Errorf("a resend on the bound connection is answered %q, want %q", got, want)
	}
}

// A resend under another AUTH_SYS uid is a false retry: no cached byte, and
// neither the slot's key nor its reply overwritten; the first uid still gets
// its reply, in any order of its groups (RFC 8881 section 2.10.6.1.3.1).
func TestAResendUnderAnotherUIDIsAFalseRetry(t *testing.T) {
	s := newSlotted(t)
	h, rel := s.admit(s.call(0x10, 1, 0, true, 1000, 4, 24))
	s.w.Store(h, &resources.Buf{B: replyOf(0x10, "first")})
	rel()

	other := headOf(s.call(0x10, 1, 0, true, 1001, 4, 24))
	if got := s.hit(other); got != nil {
		t.Errorf("another uid is answered %x", got)
	}

	if st := s.sess.Check(0, 1, s.keyOf(other), nil); st != SlotFalseRetry {
		t.Errorf("another uid is %v, want %v", st, SlotFalseRetry)
	}

	s.w.Store(other, &resources.Buf{B: replyOf(0x10, "stranger")})

	for name, b := range map[string][]byte{
		"the first uid":       s.call(0x10, 1, 0, true, 1000, 4, 24),
		"its groups reversed": s.call(0x10, 1, 0, true, 1000, 24, 4),
	} {
		if got, want := s.hit(headOf(b)), replyOf(0x10, "first"); !bytes.Equal(got, want) {
			t.Errorf("%s is answered %q, want %q", name, got, want)
		}
	}
}

// The key holds the RPCSEC_GSS service: a request resent under integrity where
// it was sent under privacy is a false retry (RFC 21 section 3.1).
func TestAResendUnderAnotherGSSServiceIsAFalseRetry(t *testing.T) {
	s := newSlotted(t)
	b := s.call(0x10, 1, 0, true, 1000)
	krb5p := gssHeader{header: header{rec: &resources.Buf{B: b}}, principal: "alice@R", service: 3}
	krb5i := gssHeader{header: header{rec: &resources.Buf{B: b}}, principal: "alice@R", service: 2}

	rel, err := s.f.Admit(context.Background(), krb5p)
	if err != nil {
		t.Fatal(err)
	}

	s.w.Store(krb5p, &resources.Buf{B: replyOf(0x10, "private")})
	rel()

	if got := s.hit(krb5i); got != nil {
		t.Errorf("a resend under integrity is answered %x", got)
	}

	if st := s.sess.Check(0, 1, callerKey(krb5i), nil); st != SlotFalseRetry {
		t.Errorf("a resend under integrity is %v, want %v", st, SlotFalseRetry)
	}

	again := gssHeader{header: header{rec: &resources.Buf{B: b}}, principal: "alice@R", service: 3}
	if got, want := s.hit(again), replyOf(0x10, "private"); !bytes.Equal(got, want) {
		t.Errorf("a resend under privacy is answered %q, want %q", got, want)
	}
}

// A sequence two ahead is misordered and a slot past the table is bad.
func TestSlotSequencesAreChecked(t *testing.T) {
	s := newSlotted(t)

	key := s.keyOf(headOf(s.call(1, 1, 0, true, 1000)))
	if st := s.sess.Check(0, 2, key, nil); st != SlotMisordered {
		t.Errorf("a sequence two ahead is %v, want %v", st, SlotMisordered)
	}

	if st := s.sess.Check(4, 1, key, nil); st != SlotBadSlot {
		t.Errorf("a slot past the table is %v, want %v", st, SlotBadSlot)
	}
}

// A slot never used takes the sequence ID 1 and no other: 0, which the slot's
// empty last request would otherwise answer as its own retry, 2 and 0xFFFFFFFF
// are misordered, under the key 0 an empty slot holds too (RFC 8881 section
// 18.36.3).
func TestAFreshSlotTakesOnlySequenceOne(t *testing.T) {
	s := newSlotted(t)

	for slot := range uint32(4) {
		for _, seq := range []uint32{0, 2, 0xFFFFFFFF} {
			for _, key := range []uint64{0, 7} {
				if st := s.sess.Check(slot, seq, key, nil); st != SlotMisordered {
					t.Errorf("sequence %#x on the fresh slot %d under key %d is %v, want %v",
						seq, slot, key, st, SlotMisordered)
				}
			}
		}

		if st := s.sess.Check(slot, 1, 7, nil); st != SlotNew {
			t.Errorf("sequence 1 on the fresh slot %d is %v, want %v", slot, st, SlotNew)
		}
	}
}

// A slot answers the sequence ID after the last one it ended, and the ID
// 0xFFFFFFFF is followed by 0: a slot that took 0xFFFFFFFF through Begin and
// Commit answers 0 as its next, 0xFFFFFFFF as its retry and 1 as misordered.
func TestASlotWraps(t *testing.T) {
	s := newSlotted(t)
	key := s.keyOf(headOf(s.call(1, 1, 0, true, 1000)))
	// a slot cannot be run through four billion requests.
	s.sess.tab.s[0].seq, s.sess.tab.s[0].used = 0xFFFFFFFF-1, true

	owner := new(resources.Buf)
	if st := s.sess.Begin(0, 0xFFFFFFFF, key, owner); st != SlotNew {
		t.Fatalf("0xFFFFFFFF after 0xFFFFFFFE is %v, want %v", st, SlotNew)
	}

	if !s.sess.Commit(0, owner, []byte("r"), true) {
		t.Fatal("the request that holds the mark commits nothing")
	}

	s.sess.Release(0, owner)

	if st := s.sess.Check(0, 0xFFFFFFFF, key, nil); st != SlotReplay {
		t.Errorf("0xFFFFFFFF again is %v, want %v", st, SlotReplay)
	}

	if st := s.sess.Check(0, 0, key, nil); st != SlotNew {
		t.Errorf("0 after 0xFFFFFFFF is %v, want %v", st, SlotNew)
	}

	if st := s.sess.Check(0, 1, key, nil); st != SlotMisordered {
		t.Errorf("1 after 0xFFFFFFFF is %v, want %v", st, SlotMisordered)
	}
}

// TestAReleaseOrCommitBeyondTheTableChangesNothing: a client's slot ID is its
// own, so a slot past the table's 4 reaching Release or Commit is a no-op, and
// the slots are as they were.
func TestAReleaseOrCommitBeyondTheTableChangesNothing(t *testing.T) {
	s := newSlotted(t)
	owner := new(resources.Buf)

	if s.sess.Begin(0, 1, 0, owner) != SlotNew {
		t.Fatal("slot 0 did not take sequence 1")
	}

	for _, id := range []uint32{4, 99, 0xFFFFFFFF} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Release on slot %#x of a 4-slot table panicked: %v", id, r)
				}
			}()

			s.sess.Release(id, owner)
		}()

		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Commit on slot %#x of a 4-slot table panicked: %v", id, r)
				}
			}()

			if s.sess.Commit(id, owner, []byte("reply"), true) {
				t.Errorf("Commit on slot %#x of a 4-slot table committed", id)
			}
		}()
	}

	if st := s.sess.Check(0, 1, 0, nil); st != SlotBusy {
		t.Errorf("slot 0 says %v after the calls beyond the table, want %v", st, SlotBusy)
	}
}

// A Release by an owner that no longer holds the mark frees nothing: the
// request that holds it keeps it. The flow does release twice for one request
// (SEQUENCE on a refused bind, then the flow's own after the store), so the
// second must not free a later request's mark.
func TestAReleaseByAnotherOwnerKeepsTheMark(t *testing.T) {
	s := newSlotted(t)
	a, b := new(resources.Buf), new(resources.Buf)

	if s.sess.Begin(0, 1, 7, a) != SlotNew {
		t.Fatal("A did not take slot 0")
	}

	s.sess.Release(0, a)

	if s.sess.Begin(0, 1, 7, b) != SlotNew {
		t.Fatal("B did not take the slot A released")
	}

	s.sess.Release(0, a)

	if st := s.sess.Check(0, 1, 7, nil); st != SlotBusy {
		t.Errorf("slot 0 after A's second release is %v, want %v", st, SlotBusy)
	}

	if s.sess.Begin(1, 1, 7, a) != SlotNew {
		t.Fatal("A did not take slot 1")
	}

	s.sess.Release(1, b)

	if st := s.sess.Check(1, 1, 7, nil); st != SlotBusy {
		t.Errorf("slot 1 after B's release of A's mark is %v, want %v", st, SlotBusy)
	}
}

// A busy slot answers any sequence ID but its own as misordered, and its own
// as busy (RFC 8881 section 2.10.6.1.3).
func TestABusySlotSaysMisorderedForAnotherSequence(t *testing.T) {
	s := newSlotted(t)

	if s.sess.Begin(0, 1, 7, new(resources.Buf)) != SlotNew {
		t.Fatal("slot 0 did not take sequence 1")
	}

	if st := s.sess.Check(0, 3, 7, nil); st != SlotMisordered {
		t.Errorf("sequence 3 on a slot busy with 1 is %v, want %v", st, SlotMisordered)
	}

	if st := s.sess.Check(0, 1, 7, nil); st != SlotBusy {
		t.Errorf("sequence 1 on a slot busy with 1 is %v, want %v", st, SlotBusy)
	}
}

// commitOne runs one request through slot 0: Begin, Commit, Release.
func commitOne(t *testing.T, s *Session, seq uint32, reply string, cache bool) {
	t.Helper()

	owner := new(resources.Buf)
	if st := s.Begin(0, seq, 7, owner); st != SlotNew {
		t.Fatalf("sequence %d on slot 0 is %v, want %v", seq, st, SlotNew)
	}

	if !s.Commit(0, owner, []byte(reply), cache) {
		t.Fatalf("the request that holds the mark did not commit sequence %d", seq)
	}

	s.Release(0, owner)
}

// A slot's last request is the one committed last: after a cached request and
// an uncached one, the retry of the second is uncached, not the first's reply
// (RFC 8881 section 2.10.6.1.3).
func TestACommitReplacesTheSlotsLastRequest(t *testing.T) {
	s := newSlotted(t)

	commitOne(t, s.sess, 1, "first", true)
	commitOne(t, s.sess, 2, "second", false)

	if st := s.sess.Check(0, 2, 7, nil); st != SlotUncached {
		t.Errorf("the retry of an uncached request after a cached one is %v, want %v",
			st, SlotUncached)
	}

	if _, ok := s.sess.ReplyLen(0, 2); ok {
		t.Error("the slot keeps a reply for the uncached request")
	}
}

// Two cached requests in a row on one slot keep the second's reply alone: its
// bytes and its length, never the first's before it.
func TestASecondCachedCommitReplacesTheFirstsReply(t *testing.T) {
	s := newSlotted(t)

	commitOne(t, s.sess, 1, "first", true)
	commitOne(t, s.sess, 2, "second", true)

	if n, ok := s.sess.ReplyLen(0, 2); !ok || n != len("second") {
		t.Errorf("ReplyLen is (%d, %v), want (%d, true)", n, ok, len("second"))
	}

	if got, ok := s.sess.AppendReply(nil, 0, 2); !ok || string(got) != "second" {
		t.Errorf("the second reply is (%q, %v), want (\"second\", true)", got, ok)
	}
}

// The slot's buffer is MaxCached bytes: a reply of that size is kept, one byte
// more is not, and the retry is uncached. This is the only barrier to a larger
// reply until REP_TOO_BIG_TO_CACHE (RFC 8881 section 2.10.6.4).
func TestACommitKeepsAReplyUpToMaxCachedOnly(t *testing.T) {
	s := newSlotted(t)
	limit := int(s.sess.Fore.MaxCached)

	for i, c := range []struct {
		n    int
		want SlotState
	}{{limit, SlotReplay}, {limit + 1, SlotUncached}} {
		seq := uint32(i + 1)
		commitOne(t, s.sess, seq, string(bytes.Repeat([]byte("x"), c.n)), true)

		if st := s.sess.Check(0, seq, 7, nil); st != c.want {
			t.Errorf("the retry of a %d byte reply (MaxCached %d) is %v, want %v",
				c.n, limit, st, c.want)
		}
	}
}

// ReplyLen and AppendReply answer only for the slot's last cached request: a
// sequence ID that is not it, a request not cached, a slot past the table, and
// they append after what dst holds.
func TestTheKeptReplyIsReadOnlyForTheLastCachedRequest(t *testing.T) {
	s := newSlotted(t)

	commitOne(t, s.sess, 1, "kept", true)

	if n, ok := s.sess.ReplyLen(0, 1); !ok || n != 4 {
		t.Errorf("ReplyLen of the cached request is (%d, %v), want (4, true)", n, ok)
	}

	if got, ok := s.sess.AppendReply([]byte("ab"), 0, 1); !ok || string(got) != "abkept" {
		t.Errorf("AppendReply is (%q, %v), want (\"abkept\", true)", got, ok)
	}

	for _, c := range []struct {
		name      string
		slot, seq uint32
	}{
		{"another sequence ID", 0, 2},
		{"the one before", 0, 0},
		{"a slot never used", 1, 1},
		{"a slot past the table", 4, 1},
	} {
		if n, ok := s.sess.ReplyLen(c.slot, c.seq); ok || n != 0 {
			t.Errorf("ReplyLen for %s is (%d, %v), want (0, false)", c.name, n, ok)
		}

		if got, ok := s.sess.AppendReply([]byte("ab"), c.slot, c.seq); ok || string(got) != "ab" {
			t.Errorf("AppendReply for %s is (%q, %v), want (\"ab\", false)", c.name, got, ok)
		}
	}

	commitOne(t, s.sess, 2, "gone", false)

	if _, ok := s.sess.ReplyLen(0, 2); ok {
		t.Error("ReplyLen answers for a request not cached")
	}

	if got, ok := s.sess.AppendReply(nil, 0, 2); ok || len(got) != 0 {
		t.Errorf("AppendReply answers for a request not cached: (%q, %v)", got, ok)
	}
}

// A request with no owner holds no mark, so it commits nothing.
func TestACommitWithoutAnOwnerCommitsNothing(t *testing.T) {
	s := newSlotted(t)

	if s.sess.Begin(0, 1, 7, nil) != SlotNew {
		t.Fatal("slot 0 did not take sequence 1")
	}

	if s.sess.Commit(0, nil, []byte("reply"), true) {
		t.Error("a nil owner committed")
	}

	if st := s.sess.Check(0, 1, 7, nil); st != SlotBusy {
		t.Errorf("slot 0 after the refused commit is %v, want %v", st, SlotBusy)
	}
}

// A cached reply's buffer is one per slot, made at its first cached Store, and
// the session's charge, which already counts it, returns when the session ends.
func TestTheSlotChargeReturnsWithTheSession(t *testing.T) {
	s := newSlotted(t)

	before := s.reg.budget.Reserved()
	if before == 0 {
		t.Fatal("a session holds no charge")
	}

	s.reg.End(s.sess.ID)

	if got := s.reg.budget.Reserved(); got != 0 {
		t.Errorf("the pool still holds %d after the session ended", got)
	}
}

// Admit, a lookup that finds nothing, an uncached Store and a cached Store after
// the slot's first allocate nothing (RFC 21 section 2.5).
func TestSlotPathsAllocateNothing(t *testing.T) {
	if prof.RaceEnabled {
		t.Skip("the allocation count says nothing under the detector")
	}

	s := newSlotted(t)
	r := &resources.Buf{B: replyOf(0x10, "reply")}
	cases := map[string]func(){}
	seq := uint32(0)
	next := func(cache bool) (core.Header, func()) {
		seq++
		return s.admit(s.call(0x10, seq, 0, cache, 1000))
	}
	h, rel := next(true)
	s.w.Store(h, r) // the first cached Store makes the slot's buffer
	rel()

	flow := headOf(s.call(0x10, 2, 1, false, 1000))
	cases["Admit"] = func() {
		rel, _ := s.f.Admit(context.Background(), flow)
		rel()
	}
	cases["a lookup that finds nothing"] = func() { _, _ = s.w.Lookup(context.Background(), flow) }

	for _, cache := range []bool{false, true} {
		hh := headOf(s.call(0x10, 1, 2, cache, 1000))

		name := "an uncached Store"
		if cache {
			name = "a cached Store after the first"
		}

		cases[name] = func() {
			rel, _ := s.f.Admit(context.Background(), hh)
			s.w.Store(hh, r)
			rel()

			s.sess.tab.s[2].seq = 0
		}
	}

	for name, f := range cases {
		if n := testing.AllocsPerRun(200, f); n != 0 {
			t.Errorf("%s allocates %v per call", name, n)
		}
	}
}

// Route gives a COMPOUND of minor version 1 whose first operation is SEQUENCE
// what that operation's member judges and the call's session and client, and
// starts it negotiated; one of minor version 0 starts at the session level and
// reads no SEQUENCE; a session the node does not hold leaves the call's
// session and client zero (RFC 21 sections 3.1 and 11.5).
func TestRouteReadsTheSequenceAndStartsTheLevel(t *testing.T) {
	s := newSlotted(t)
	s.w.conn = nil // a bare connection panics where Route establishes it

	h := headOf(s.call(1, 1, 0, false, 1000))

	_, r, err := s.w.Route(h, nil)
	if err != nil {
		t.Fatal(err)
	}

	st := r.State.(*State)

	if r.Level != core.NeedsNegotiated {
		t.Errorf("the level is %d, want negotiated %d", r.Level, core.NeedsNegotiated)
	}

	if r.Call.Session != s.sess.Ref || r.Call.Client != s.sess.Client {
		t.Errorf("the call's session and client are %v and %v, want %v and %v",
			r.Call.Session, r.Call.Client, s.sess.Ref, s.sess.Client)
	}

	if !st.SeqFirst || st.SeqKey != callerKey(h) || st.SeqOwner != h.(header).rec {
		t.Errorf("the state holds %v, %d and %p, want true, the caller's key and the record",
			st.SeqFirst, st.SeqKey, st.SeqOwner)
	}

	gone := s.call(2, 1, 0, false, 1000)
	copy(gone[len(gone)-32:], make([]byte, 16))

	_, r, err = s.w.Route(headOf(gone), nil)
	if err != nil {
		t.Fatal(err)
	}

	if r.Call.Session != (vfs.SessionRef{}) || r.Call.Client != 0 || !r.State.(*State).SeqFirst {
		t.Errorf("a session the node lacks left the call %v and %v", r.Call.Session, r.Call.Client)
	}

	zero := stageOf(settings.VersionRange{Min: "3", Max: "4.2"})
	body := nullCall(
		wire.ProgNFS,
		wire.VersNFS4,
		wire.ProcCompound,
		wire.AuthNone,
		nil,
		wire.AuthNone,
		nil,
		binary.BigEndian.AppendUint32(
			binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, 0), 0),
			0,
		),
	)

	_, r, err = zero.Route(headOf(body), nil)
	if err != nil {
		t.Fatal(err)
	}

	if r.Level != core.NeedsSession || r.State.(*State).SeqFirst {
		t.Errorf("minor 0 starts at level %d with SeqFirst %v, want the session level and false",
			r.Level, r.State.(*State).SeqFirst)
	}
}

// Routing a COMPOUND that opens with SEQUENCE stays at the one allocation a
// COMPOUND's request and state take, the session lookup and the key included.
func TestRoutingASequenceCompoundAllocatesOneRequest(t *testing.T) {
	if prof.RaceEnabled {
		t.Skip("the allocation count says nothing under the detector")
	}

	s := newSlotted(t)
	s.w.conn = nil

	h := headOf(s.call(1, 1, 0, true, 1000, 1, 2, 3))

	if n := testing.AllocsPerRun(100, func() {
		if _, _, err := s.w.Route(h, nil); err != nil {
			t.Fatal(err)
		}
	}); n != 1 {
		t.Errorf("routing a SEQUENCE COMPOUND allocates %v per call, want 1", n)
	}
}
