//go:build !linux

package main

// listenersOn cannot name a port's owner off Linux, where there is no /proc
// socket table to read. Returning nothing makes diag.PortConflict fall back to
// telling the operator which command to run, which is better than a guess.
func listenersOn(proto, addr string) []string { return nil }
