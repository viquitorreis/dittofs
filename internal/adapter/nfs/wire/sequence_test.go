package wire_test

import (
	"encoding/binary"
	"testing"

	"github.com/cubbit/dittofs/internal/adapter/nfs/wire"
	"github.com/cubbit/dittofs/internal/prof"
)

// seqCall builds a COMPOUND call, AUTH_NONE, with the given tag and minor
// version, whose operations are ops (each already encoded): the count, then
// the operations.
func seqCall(tag string, minor uint32, count uint32, ops []byte) []byte {
	u := binary.BigEndian.AppendUint32
	c := u(nil, 7)
	c = u(c, 0)
	c = u(c, 2)
	c = u(c, wire.ProgNFS)
	c = u(c, wire.VersNFS4)
	c = u(c, wire.ProcCompound)
	c = u(c, wire.AuthNone)
	c = u(c, 0)
	c = u(c, wire.AuthNone)
	c = u(c, 0)
	c = u(c, uint32(len(tag)))

	c = append(c, tag...)
	for len(c)%4 != 0 {
		c = append(c, 0)
	}

	c = u(c, minor)
	c = u(c, count)

	return append(c, ops...)
}

// seqOp encodes a SEQUENCE operation: its code, the session ID, the sequence
// ID, the slot ID, the highest slot ID and cachethis (RFC 8881 section
// 18.46.1).
func seqOp(id [16]byte, seq, slot, high uint32, cache bool) []byte {
	u := binary.BigEndian.AppendUint32
	b := u(nil, 53)
	b = append(b, id[:]...)
	b = u(b, seq)
	b = u(b, slot)

	b = u(b, high)
	if cache {
		return u(b, 1)
	}

	return u(b, 0)
}

func TestSequenceFieldsAreReadFromTheCompoundHead(t *testing.T) {
	id := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	rec := seqCall("tg", 1, 2, append(seqOp(id, 0xfffffffe, 5, 9, true), 0, 0, 0, 22))

	c, err := wire.ParseCall(rec)
	if err != nil {
		t.Fatal(err)
	}

	s, ok := c.Sequence()
	if !ok {
		t.Fatal("a minor version 1 COMPOUND opening with SEQUENCE reads no sequence fields")
	}

	if s.Session != id || s.SeqID != 0xfffffffe || s.Slot != 5 || s.HighestSlot != 9 ||
		!s.CacheThis {
		t.Errorf("sequence fields %+v", s)
	}

	rec = seqCall("", 2, 1, seqOp(id, 1, 0, 0, false))

	c, _ = wire.ParseCall(rec)
	if s, ok = c.Sequence(); !ok || s.CacheThis || s.SeqID != 1 || s.Slot != 0 {
		t.Errorf("a minor version 2 call with cachethis false reads %+v, %v", s, ok)
	}
}

func TestSequenceIsAbsentWhenTheHeadIsNotSequence(t *testing.T) {
	id := [16]byte{1}
	// cachethis is an XDR bool: any word past 1 is no boolean, and the
	// operation's decoder refuses it, so the head reads no SEQUENCE.
	notBool := seqOp(id, 1, 0, 0, true)
	binary.BigEndian.PutUint32(notBool[len(notBool)-4:], 2)

	for name, rec := range map[string][]byte{
		"minor 0":       seqCall("", 0, 1, seqOp(id, 1, 0, 0, false)),
		"another op":    seqCall("", 1, 1, []byte{0, 0, 0, 22}),
		"no operations": seqCall("", 1, 0, nil),
		"cut in the id": seqCall("", 1, 1, seqOp(id, 1, 0, 0, false)[:12]),
		"cut in cache":  seqCall("", 1, 1, seqOp(id, 1, 0, 0, false)[:32]),
		"empty ops":     seqCall("", 1, 1, nil),
		"cachethis 2":   seqCall("", 1, 1, notBool),
	} {
		c, _ := wire.ParseCall(rec)
		if s, ok := c.Sequence(); ok {
			t.Errorf("%s: sequence fields %+v are read", name, s)
		}
	}
}

func TestSequenceReadAllocatesNothing(t *testing.T) {
	if prof.RaceEnabled {
		t.Skip("the allocation count says nothing under the detector")
	}

	rec := seqCall("t", 1, 1, seqOp([16]byte{9}, 3, 1, 1, true))
	c, _ := wire.ParseCall(rec)

	if n := testing.AllocsPerRun(1000, func() { _, _ = c.Sequence() }); n != 0 {
		t.Errorf("Sequence allocates %v per call", n)
	}
}

// framed puts a record mark, a last fragment, in front of a call.
func framed(call []byte) []byte {
	return append(binary.BigEndian.AppendUint32(nil, 0x80000000|uint32(len(call))), call...)
}
