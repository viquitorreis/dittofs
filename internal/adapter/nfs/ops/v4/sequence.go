package v4

import (
	"context"

	"github.com/cubbit/dittofs/internal/adapter/core"
	"github.com/cubbit/dittofs/internal/adapter/nfs/protocol"
	"github.com/cubbit/dittofs/pkg/vfs"
)

// sequenceArgs is SEQUENCE4args.
type sequenceArgs struct {
	SessionID   [16]byte
	SequenceID  uint32
	SlotID      uint32
	HighestSlot uint32
	CacheThis   bool
}

// sequenceRes is SEQUENCE4res past its status.
type sequenceRes struct {
	Ok *sequenceResOk `xdr:"arm"`
}

// sequenceResOk is SEQUENCE4resok.
type sequenceResOk struct {
	SessionID     [16]byte
	SequenceID    uint32
	SlotID        uint32
	HighestSlot   uint32
	TargetHighest uint32
	StatusFlags   uint32
}

// Sequence answers SEQUENCE (RFC 8881 section 18.46; RFC 21 section 3.1): it
// judges the slot the call named, which the connection's flow already marked in
// flight for this request, and raises the request to the session level. A
// refusal is its status alone and leaves the slot as it was: the refusals that
// come before the slot's verdict hold no mark, and the one after the mark was
// taken, a connection not bound to the session, frees it, so the cache stores
// nothing in the slot (RFC 8881 section 2.10.6.1.2). The reply of a request that
// ran is stored, with the slot's sequence ID, by the cache once the whole reply
// is encoded. The retry of a request whose reply was not kept is the one
// exception: SEQUENCE is answered as it was and the members after it refuse.
//
// ponytail: both highest slot IDs the reply carries are the highest slot the
// session was granted, whatever sa_highest_slotid says: that field is the
// client's own highest slot in use, not a retirement, and a client retires a
// slot only after the server lowers sr_target_highest_slotid, which it never
// does. Revisit when slots shrink.
//
// ponytail: the reply's status flags are zero: no back channel fault, revoked
// state or lease signal is reported yet. Set them where the lease and the
// callbacks raise one.
func (h *Handlers) Sequence(
	_ context.Context,
	r *core.Request,
	a sequenceArgs,
) (sequenceRes, error) {
	st := r.State.(*protocol.State)

	if !st.SeqFirst || r.Level&^core.NeedsFH >= core.NeedsSession {
		return sequenceRes{}, errSequencePos
	}

	sess, ok := h.Sessions.Get(protocol.SessionID(a.SessionID))
	if !ok {
		return sequenceRes{}, errBadSession
	}

	if st.Bound != nil && !st.Bound.Has(sess.ID) {
		// decision: a connection not bound to the session is bound by its
		// SEQUENCE unless the client's record is SP4_MACH_CRED, which has it
		// bind with BIND_CONN_TO_SESSION first (RFC 8881 section 2.10.3.1 and
		// section 18.46.3). Overturned when the record's must-enforce list
		// names BIND_CONN_TO_SESSION and the rule reads it.
		if sess.Protect || !h.Sessions.Bind(sess, st.Bound) {
			// The flow marked the slot busy for this request when it was the
			// slot's next: free it, so the reply the cache then stores commits
			// nothing and the client's resend, once it binds, runs.
			sess.Release(a.SlotID, st.SeqOwner)

			return sequenceRes{}, errConnNotBound
		}
	}

	switch sess.Check(a.SlotID, a.SequenceID, st.SeqKey, st.SeqOwner) {
	case protocol.SlotNew:
		// A request the flow did not mark, because the slot was busy when it
		// came in, is not admitted for the slot even if the slot is free now:
		// it would commit nothing and leave the client's next sequence ID out
		// of order.
		if !sess.HoldsMark(a.SlotID, st.SeqOwner) {
			return sequenceRes{}, &vfs.Delay{Cause: vfs.DelayConflict}
		}
	case protocol.SlotBadSlot:
		return sequenceRes{}, errBadSlot
	case protocol.SlotMisordered:
		return sequenceRes{}, errMisordered
	case protocol.SlotFalseRetry:
		return sequenceRes{}, errFalseRetry
	case protocol.SlotUncached:
		// decision: the retry of a request whose reply was not kept is answered
		// SEQUENCE's own results, status NFS4_OK, and the member after it is
		// the one that answers NFS4ERR_RETRY_UNCACHED_REP, which protocol.New
		// has every other row do before it resolves anything (RFC 8881 section
		// 2.10.6.1.3). SEQUENCE must not return that status as the first
		// operation, and the slot's reply is left as it was: the request took no
		// mark, so the cache stores nothing for it. Overturned if a client is
		// seen needing the status on SEQUENCE.
		st.Uncached = true
	default:
		// A busy slot, or a retry whose reply the cache answers before the
		// member runs: seen here, the request was not admitted for its slot.
		return sequenceRes{}, &vfs.Delay{Cause: vfs.DelayConflict}
	}

	r.Level |= core.NeedsSession

	highest := sess.Fore.Slots - 1

	return sequenceRes{Ok: &sequenceResOk{
		SessionID:     a.SessionID,
		SequenceID:    a.SequenceID,
		SlotID:        a.SlotID,
		HighestSlot:   highest,
		TargetHighest: highest,
	}}, nil
}
