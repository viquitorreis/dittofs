package protocol

import (
	"errors"

	"github.com/cubbit/dittofs/internal/adapter/core"
	"github.com/cubbit/dittofs/internal/adapter/nfs/wire"
)

// ErrRetryUncached is the refusal of a member after the SEQUENCE of a retry
// whose reply the slot did not keep (RFC 8881 section 2.10.6.1.3): it maps to
// NFS4ERR_RETRY_UNCACHED_REP.
var ErrRetryUncached = errors.New("nfs4: a retry of a request whose reply was not kept")

// opIllegal is ILLEGAL's operation code, the row every undefined code reaches.
const opIllegal = 10044

// opSequence is SEQUENCE's operation code.
const opSequence = 53

// refuseAfterUncached makes every member row of t's COMPOUND but ILLEGAL and
// SEQUENCE resolve to ErrRetryUncached while State.Uncached is set, which is
// before it reads a name or runs a handler, so the retry changes nothing. A
// member the row refuses first, an operation the minor version does not serve,
// one not supported, one needing a current filehandle the retry has not put,
// is answered that refusal, which is what the RFC asks of an illegal second
// operation (RFC 8881 section 2.10.6.1.3). It is done here, over the table the
// protocol was handed, so a row added later, or a test's, is covered. SEQUENCE
// is left as it is: a second SEQUENCE in the retry answers its own
// NFS4ERR_SEQUENCE_POS, which the RFC allows (section 2.10.6.1.3).
//
// ponytail: a closure per decoded v4.1 member, the cost of wrapping Resolve,
// which the row's own Hooks cannot reach without every row naming the rule. Move
// the State.Uncached check into core's resolve if the allocation shows in a
// profile.
func refuseAfterUncached(t *core.OpTable) {
	if t == nil {
		return
	}

	compound := t.Ops[wire.ProcCompound]
	if compound == nil || compound.Members == nil {
		return
	}

	for code, op := range compound.Members.Ops {
		if code == opIllegal || code == opSequence {
			continue
		}

		decode := op.Decode
		op.Decode = func(body []byte, v core.Version) (core.Invocation, int, error) {
			inv, n, err := decode(body, v)
			if err != nil || inv.Resolve == nil {
				return inv, n, err
			}

			resolve := inv.Resolve
			inv.Resolve = func(r *core.Request) error {
				if st, ok := r.State.(*State); ok && st.Uncached {
					return ErrRetryUncached
				}

				return resolve(r)
			}

			return inv, n, err
		}
	}
}
