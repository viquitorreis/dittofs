package adaptertest

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/cubbit/dittofs/internal/adapter/core"
)

// nothing is a header no flow reads: the conformance's flows here admit on the
// place alone.
type nothing struct{}

func (nothing) Op() uint32            { return 0 }
func (nothing) Version() core.Version { return 0 }
func (nothing) Next() int             { return 0 }
func (nothing) Related() bool         { return false }

// semaphore is a flow of n places. A place's release frees it once. With
// deaf, Admit never looks at its context: it waits for a place however its
// context ends. With wrong, a full flow's refusal is an error that is not the
// context's.
type semaphore struct {
	places chan struct{}
	deaf   bool
	wrong  bool
}

func newSemaphore(n int, deaf bool) *semaphore {
	return &semaphore{places: make(chan struct{}, n), deaf: deaf}
}

func (s *semaphore) Admit(ctx context.Context, _ core.Header) (func(), error) {
	select {
	case s.places <- struct{}{}:
	default:
		if s.deaf {
			s.places <- struct{}{}

			break
		}

		select {
		case s.places <- struct{}{}:
		case <-ctx.Done():
			if s.wrong {
				return nil, errors.New("full")
			}

			return nil, ctx.Err()
		}
	}

	var once sync.Once

	return func() { once.Do(func() { <-s.places }) }, nil
}

// unlimited is a flow with no cap that refuses nothing.
type unlimited struct{}

func (unlimited) Admit(context.Context, core.Header) (func(), error) { return func() {}, nil }

// A flow of the right cap that answers an ended context at once conforms,
// and so does one with no cap.
func TestFlowConformanceAcceptsAFlowThatKeepsItsContract(t *testing.T) {
	FlowConformance(t, func() core.FlowControl { return newSemaphore(64, false) }, nothing{}, 64)
	FlowConformance(t, func() core.FlowControl { return unlimited{} }, nothing{}, 0)
}

// Each flow that breaks the contract is named by the problem it breaks: the
// wrong cap either way, one that waits under an ended context, and one that
// has a cap where none was declared.
func TestFlowConformanceNamesWhatAFlowBreaks(t *testing.T) {
	for _, tc := range []struct {
		name     string
		flow     func() core.FlowControl
		capacity int
		want     string
	}{
		{"a cap of 65", func() core.FlowControl { return newSemaphore(65, false) }, 64, "65th"},
		{"a cap of 63", func() core.FlowControl {
			return newSemaphore(63, false)
		}, 64, "with a place free"},
		{"waiting under an ended context", func() core.FlowControl {
			return newSemaphore(64, true)
		}, 64, "ended context"},
		{"an error that is not the context's", func() core.FlowControl {
			return &semaphore{places: make(chan struct{}, 64), wrong: true}
		}, 64, "ended context"},
		{"no cap where 64 are declared", func() core.FlowControl {
			return unlimited{}
		}, 64, "65th"},
		{"a cap where none is declared", func() core.FlowControl {
			return newSemaphore(1, false)
		}, 0, "no cap"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := flowProblems(t, tc.flow, nothing{}, tc.capacity)
			if len(got) == 0 {
				t.Fatal("no problem found, want one")
			}

			if !strings.Contains(strings.Join(got, "\n"), tc.want) {
				t.Errorf("problems %q, want one naming %q", got, tc.want)
			}
		})
	}
}
