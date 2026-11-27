package protocol

import (
	"context"
	"encoding/binary"
	"hash/maphash"
	"slices"
	"sync"

	"github.com/cubbit/dittofs/internal/adapter/core"
	"github.com/cubbit/dittofs/internal/adapter/nfs/wire"
	"github.com/cubbit/dittofs/pkg/resources"
)

// flowCap is how many requests a connection has in flight at once, counted at
// admit (RFC 20 section 6.3), the number core's default flow gives it.
//
// ponytail: a fixed cap of 64 for each connection. Size it from the sessions'
// slots when a client holding more of them is limited by it.
const flowCap = 64

// recorded is a header that reads its call where it lies and names the record
// it came in, which is what a slot's mark is held by (RFC 21 section 3.1).
type recorded interface {
	call() wire.Call
	record() *resources.Buf
}

// secured is a header whose call arrived under RPCSEC_GSS: the principal and
// the service it was protected under, which a caller's key holds.
//
// decision: no production header implements it yet, because the RPCSEC_GSS
// unwrap that sets the principal and the service does not exist; the key holds
// both at once, so a reply stored under one protection is no hit for a retry
// under another, and the tests give it headers that carry them. Overturned if
// the unwrap passes the identity to the key another way.
type secured interface {
	gssIdentity() (principal string, service uint32)
}

// callerKey is the hash of who sent the request: the flavour, the AUTH_SYS uid,
// gid and groups, in any order, and the RPCSEC_GSS principal and service. A
// retry under another key is a false retry (RFC 8881 section 2.10.6.1.3.1).
// It allocates nothing.
func callerKey(h core.Header) uint64 {
	hd, ok := h.(recorded)
	if !ok {
		return 0
	}

	var m maphash.Hash
	m.SetSeed(replaySeed)

	c := hd.call()

	flavour, sys, err := checkAuth(c)
	if err != nil {
		flavour = ^uint32(0)
	}

	var gids [16]uint32

	n := copy(gids[:], sys.Groups())
	slices.Sort(gids[:n])

	var b [4]byte

	for _, v := range [...]uint32{flavour, sys.UID, sys.GID, uint32(n)} {
		binary.BigEndian.PutUint32(b[:], v)
		_, _ = m.Write(b[:])
	}

	for _, g := range gids[:n] {
		binary.BigEndian.PutUint32(b[:], g)
		_, _ = m.Write(b[:])
	}

	if g, ok := h.(secured); ok {
		principal, service := g.gssIdentity()
		binary.BigEndian.PutUint32(b[:], service)
		_, _ = m.Write(b[:])
		_, _ = m.WriteString(principal)
	}

	return m.Sum64()
}

// Flow is one connection's flow control: a counting semaphore of flowCap places, and
// for a request that opens with SEQUENCE the mark on its slot, taken at admit
// and cleared at release, which lies after the reply is stored (RFC 20 section
// 4.7, RFC 21 section 3.1).
//
// decision: Flow keeps the cap of each connection itself and marks a request's
// slot without waiting for it, so a busy slot is SEQUENCE's NFS4ERR_DELAY and
// one client's slot never stops the connection's reader (RFC 20 section 6.3).
// Overturned if core's flow control must hold a request until its slot is free.
type Flow struct {
	places chan struct{}
	reg    *Sessions
	pool   sync.Pool
}

// NewFlow is a flow whose SEQUENCE calls find their slots in reg; nil: none.
func NewFlow(reg *Sessions) *Flow {
	f := &Flow{places: make(chan struct{}, flowCap), reg: reg}
	f.pool.New = func() any {
		a := &admission{f: f}
		a.fn = a.release

		return a
	}

	return f
}

// admission is what one Admit holds: the semaphore's place and the slot mark,
// pooled with its release method value so an admit allocates nothing.
type admission struct {
	f     *Flow
	fn    func()
	sess  *Session
	slot  uint32
	owner *resources.Buf
}

// release clears the slot's mark if the request still holds it, then frees the
// place. It is called once, by core.
func (a *admission) release() {
	if a.sess != nil {
		a.sess.Release(a.slot, a.owner)
	}

	f := a.f
	a.sess, a.owner = nil, nil

	f.pool.Put(a)
	<-f.places
}

// Admit takes a place, waiting within ctx for one to free, and marks the slot
// h's SEQUENCE names busy when the request is its next. A request the slot
// says is a retry, or is wrong, is admitted all the same, with no mark: the
// lookup after it answers it.
func (f *Flow) Admit(ctx context.Context, h core.Header) (release func(), err error) {
	select {
	case f.places <- struct{}{}:
	default:
		select {
		case f.places <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	a := f.pool.Get().(*admission)

	if sess, seq, ok := sequenceOf(f.reg, h); ok {
		if sess.Begin(seq.Slot, seq.SeqID, callerKey(h), h.(recorded).record()) == SlotNew {
			a.sess, a.slot, a.owner = sess, seq.Slot, h.(recorded).record()
		}
	}

	return a.fn, nil
}

// sequenceOf is the session and the SEQUENCE a call of minor version 1 or more
// opens with, when reg holds the session.
func sequenceOf(reg *Sessions, h core.Header) (*Session, wire.Sequence, bool) {
	hd, ok := h.(recorded)
	if !ok || reg == nil {
		return nil, wire.Sequence{}, false
	}

	seq, ok := hd.call().Sequence()
	if !ok {
		return nil, wire.Sequence{}, false
	}

	sess, ok := reg.Get(seq.Session)

	return sess, seq, ok
}
