package protocol

import (
	"sync"

	"github.com/cubbit/dittofs/pkg/resources"
)

// SlotState is what a slot says of a SEQUENCE's sequence ID (RFC 8881 section
// 2.10.6.1.3).
type SlotState int

const (
	SlotNew        SlotState = iota // the next sequence ID, or one whose mark is held: run it
	SlotReplay                      // a retry of the last request, whose reply is kept
	SlotUncached                    // a retry of the last request, whose reply was not kept
	SlotBusy                        // the request in flight: NFS4ERR_DELAY
	SlotFalseRetry                  // the last sequence ID under another caller's key
	SlotMisordered                  // any other sequence ID
	SlotBadSlot                     // a slot past the table
)

// slot is one slot of a session's fore channel: the sequence ID of the last
// request that ended and the caller's key it came with, its reply when the
// client asked for it kept, and the request in flight, if any, which holds the
// slot's mark by the record's buffer it came in (RFC 21 section 3.1).
type slot struct {
	seq    uint32
	key    uint64
	cached bool
	used   bool   // a request has ended on the slot
	reply  []byte // one buffer of the channel's MaxCached, made at the first cached Commit

	busy    bool
	next    uint32
	nextKey uint64
	owner   *resources.Buf
}

// slots is the session's slot table, under its own mutex.
type slots struct {
	mu sync.Mutex
	s  []slot
}

// verdict is what slot id says of seq under key, and whether the caller, owner,
// holds the slot's mark. The table's mutex is held.
func (t *slots) verdict(id, seq uint32, key uint64, owner *resources.Buf) SlotState {
	if int(id) >= len(t.s) {
		return SlotBadSlot
	}

	sl := &t.s[id]
	if sl.busy {
		switch {
		case sl.owner == owner && owner != nil && sl.next == seq:
			return SlotNew
		case sl.next == seq:
			return SlotBusy
		}

		return SlotMisordered
	}

	switch {
	case seq == sl.seq+1:
		return SlotNew
	case !sl.used:
		// the first request on a slot has the sequence ID 1, whatever the
		// slot's empty last request holds (RFC 8881 section 18.36.3).
		return SlotMisordered
	case seq != sl.seq:
		return SlotMisordered
	case sl.key != key:
		return SlotFalseRetry
	case !sl.cached:
		return SlotUncached
	}

	return SlotReplay
}

// Check is what slot id says of seq, read where it lies: nothing is marked. A
// request whose mark owner holds is new.
func (s *Session) Check(id, seq uint32, key uint64, owner *resources.Buf) SlotState {
	s.tab.mu.Lock()

	defer s.tab.mu.Unlock()

	return s.tab.verdict(id, seq, key, owner)
}

// Begin marks slot id in flight for the request that holds owner when seq is
// its next sequence ID, and reports what the slot says.
func (s *Session) Begin(id, seq uint32, key uint64, owner *resources.Buf) SlotState {
	s.tab.mu.Lock()

	defer s.tab.mu.Unlock()

	st := s.tab.verdict(id, seq, key, owner)
	if st == SlotNew && !s.tab.s[id].busy {
		sl := &s.tab.s[id]
		sl.busy, sl.next, sl.nextKey, sl.owner = true, seq, key, owner
	}

	return st
}

// HoldsMark reports whether owner holds slot id's mark: a request that Begin
// marked, and that has not been released.
func (s *Session) HoldsMark(id uint32, owner *resources.Buf) bool {
	s.tab.mu.Lock()

	defer s.tab.mu.Unlock()

	if int(id) >= len(s.tab.s) {
		return false
	}

	sl := &s.tab.s[id]

	return sl.busy && owner != nil && sl.owner == owner
}

// Release ends the mark owner holds on slot id, if it still holds it, with the
// slot's sequence ID and reply as they were. A slot the table does not have,
// which a client's own ID can name, holds no mark: nothing happens.
func (s *Session) Release(id uint32, owner *resources.Buf) {
	s.tab.mu.Lock()

	defer s.tab.mu.Unlock()

	if int(id) >= len(s.tab.s) {
		return
	}

	if sl := &s.tab.s[id]; sl.busy && sl.owner == owner {
		sl.busy, sl.owner = false, nil
	}
}

// Commit makes the request that holds owner's sequence ID the slot's, with its
// caller's key and, where cache is set and reply fits the channel's MaxCached,
// its reply, copied into the slot's one buffer. A request that does not hold the
// slot's mark commits nothing, and neither does one for a slot the table does
// not have. The mark stays until Release.
func (s *Session) Commit(id uint32, owner *resources.Buf, reply []byte, cache bool) bool {
	s.tab.mu.Lock()

	defer s.tab.mu.Unlock()

	if int(id) >= len(s.tab.s) {
		return false
	}

	sl := &s.tab.s[id]
	if !sl.busy || sl.owner != owner || owner == nil {
		return false
	}

	sl.seq, sl.key, sl.cached, sl.used = sl.next, sl.nextKey, false, true

	if cache && len(reply) <= int(s.Fore.MaxCached) {
		if sl.reply == nil {
			sl.reply = make([]byte, 0, s.Fore.MaxCached)
		}

		sl.reply, sl.cached = append(sl.reply[:0], reply...), true
	}

	return true
}

// ReplyLen is the length of the reply slot id keeps for seq, and false when it
// keeps none for it.
func (s *Session) ReplyLen(id, seq uint32) (int, bool) {
	s.tab.mu.Lock()

	defer s.tab.mu.Unlock()

	if int(id) >= len(s.tab.s) || !s.tab.s[id].cached || s.tab.s[id].seq != seq {
		return 0, false
	}

	return len(s.tab.s[id].reply), true
}

// AppendReply appends the reply slot id keeps for seq to dst.
func (s *Session) AppendReply(dst []byte, id, seq uint32) ([]byte, bool) {
	s.tab.mu.Lock()

	defer s.tab.mu.Unlock()

	if int(id) >= len(s.tab.s) || !s.tab.s[id].cached || s.tab.s[id].seq != seq {
		return dst, false
	}

	return append(dst, s.tab.s[id].reply...), true
}
