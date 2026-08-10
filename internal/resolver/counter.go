package resolver

import "sync/atomic"

// atomicCounter is a monotonic counter used for lightweight runtime metrics.
type atomicCounter struct{ v atomic.Uint64 }

func (c *atomicCounter) inc()         { c.v.Add(1) }
func (c *atomicCounter) add(n uint64) { c.v.Add(n) }
func (c *atomicCounter) get() uint64  { return c.v.Load() }
