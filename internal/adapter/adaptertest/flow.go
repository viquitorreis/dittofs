package adaptertest

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"testing/synctest"

	"github.com/cubbit/dittofs/internal/adapter/core"
)

// FlowConformance fails t for each way the flow newFlow builds breaks what core
// asks of a protocol's flow control (RFC 20 section 6.3): given a header h it
// admits, it takes capacity requests at once and holds the next until a release
// frees a place or its context ends, and under a context already ended it tries
// once, taking a free place and otherwise returning the context's error at
// once. A capacity of 0 is a flow with no cap, which admits under any context
// and never waits. It runs in a synctest bubble, so a flow must wait on a
// channel, a context or a timer, not on a lock.
func FlowConformance(t *testing.T, newFlow func() core.FlowControl, h core.Header, capacity int) {
	t.Helper()

	for _, problem := range flowProblems(t, newFlow, h, capacity) {
		t.Error(problem)
	}
}

// waiting is an Admit run on its own goroutine, read once the bubble is idle.
type waiting struct {
	done    bool
	release func()
	err     error
}

func admitting(ctx context.Context, f core.FlowControl, h core.Header) *waiting {
	w := new(waiting)

	go func() {
		w.release, w.err = f.Admit(ctx, h)
		w.done = true
	}()

	synctest.Wait()

	return w
}

// flowProblems is the checks FlowConformance makes, each failure as a line.
func flowProblems(
	t *testing.T, newFlow func() core.FlowControl, h core.Header, capacity int,
) (problems []string) {
	t.Helper()

	synctest.Test(t, func(t *testing.T) {
		ended, end := context.WithCancel(t.Context())
		end()

		if capacity == 0 {
			problems = uncapped(newFlow(), h, ended)

			return
		}

		problems = capped(newFlow, h, ended, capacity)
	})

	return problems
}

// uncapped is the problems of a flow declared to have no cap: it admits many
// requests under an ended context, which a cap would refuse.
func uncapped(f core.FlowControl, h core.Header, ended context.Context) (problems []string) {
	var releases []func()

	defer func() {
		for _, release := range releases {
			release()
		}
	}()

	for range 200 {
		w := admitting(ended, f, h)
		if !w.done || w.err != nil {
			return append(problems, fmt.Sprintf(
				"a flow declared with no cap refused or held an Admit under an ended context "+
					"after %d admitted (done %v, err %v), want it admitted: it has a cap",
				len(releases), w.done, w.err))
		}

		releases = append(releases, w.release)
	}

	return problems
}

// capped is the problems of a flow of capacity places.
func capped(
	newFlow func() core.FlowControl, h core.Header, ended context.Context, capacity int,
) (problems []string) {
	f := newFlow()
	live := context.Background()
	releases := make([]func(), 0, capacity+1)

	defer func() {
		// the places are freed last, so an Admit that waited past its
		// contract is let go before the bubble ends.
		for _, release := range releases {
			release()
		}
	}()

	for i := range capacity {
		w := admitting(live, f, h)
		if !w.done || w.err != nil {
			return append(problems, fmt.Sprintf(
				"Admit number %d of %d with a place free = done %v, err %v, want a place",
				i+1, capacity, w.done, w.err))
		}

		releases = append(releases, w.release)
	}

	// the next waits, and a release lets it in.
	next := admitting(live, f, h)
	if next.done {
		problems = append(problems, fmt.Sprintf(
			"the %dth Admit returned (err %v) with %d in flight, want it waiting",
			capacity+1, next.err, capacity))

		if next.release != nil {
			releases = append(releases, next.release)
		}

		return problems
	}

	releases[0]()
	synctest.Wait()

	if !next.done || next.err != nil {
		return append(problems, fmt.Sprintf(
			"the %dth Admit after a release: done %v, err %v, want it admitted",
			capacity+1, next.done, next.err))
	}

	releases[0] = next.release

	// a waiting Admit leaves when its context ends.
	stop, cancel := context.WithCancel(live)

	defer cancel()

	left := admitting(stop, f, h)

	if left.done {
		return append(problems, "an Admit at the cap returned, want it waiting")
	}

	cancel()
	synctest.Wait()

	if !left.done || !errors.Is(left.err, context.Canceled) {
		problems = append(problems, fmt.Sprintf(
			"a waiting Admit whose context ended: done %v, err %v, want %v",
			left.done, left.err, context.Canceled))
	}

	// under an ended context it tries once: a full flow answers at once, a
	// free place is taken.
	refused := admitting(ended, f, h)
	if !refused.done || !errors.Is(refused.err, context.Canceled) {
		problems = append(problems, fmt.Sprintf(
			"Admit at the cap under an ended context: done %v, err %v, want %v at once",
			refused.done, refused.err, context.Canceled))
	}

	releases[0]()
	synctest.Wait()

	taken := admitting(ended, f, h)
	if !taken.done || taken.err != nil {
		problems = append(problems, fmt.Sprintf(
			"Admit with a place free under an ended context: done %v, err %v, want the place",
			taken.done, taken.err))
	} else {
		releases[0] = taken.release
	}

	return problems
}
