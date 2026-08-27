//go:build linux

package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// listenersOn names the processes holding a port, best effort.
//
// Best effort is the honest description: /proc/net gives the socket inodes
// without needing privilege, but mapping an inode to a process means reading
// /proc/<pid>/fd, which is readable only for our own processes unless we are
// root. When we cannot name the owner we say so rather than guessing, and the
// caller falls back to telling the operator which `ss` command to run.
func listenersOn(proto, addr string) []string {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil
	}

	files := []string{"/proc/net/" + proto, "/proc/net/" + proto + "6"}
	inodes := map[string]bool{}
	for _, f := range files {
		for _, inode := range socketInodesOnPort(f, port) {
			inodes[inode] = true
		}
	}
	if len(inodes) == 0 {
		return nil
	}

	owners := namesForInodes(inodes)
	if len(owners) == 0 {
		return []string{fmt.Sprintf("%d socket(s) bound to port %d, owner not readable without root", len(inodes), port)}
	}
	return owners
}

// socketInodesOnPort parses a /proc/net/{tcp,udp} table and returns the inodes
// of sockets bound to port.
func socketInodesOnPort(path string, port int) []string {
	b, err := os.ReadFile(path) // #nosec G304 -- fixed /proc paths built from a constant list
	if err != nil {
		return nil
	}

	var out []string
	for i, line := range strings.Split(string(b), "\n") {
		if i == 0 { // header
			continue
		}
		fields := strings.Fields(line)
		// local_address is field 1 ("0100007F:0035"), inode is field 9.
		if len(fields) < 10 {
			continue
		}
		local := fields[1]
		sep := strings.LastIndex(local, ":")
		if sep < 0 {
			continue
		}
		p, err := hex.DecodeString(local[sep+1:])
		if err != nil || len(p) != 2 {
			continue
		}
		if int(p[0])<<8|int(p[1]) != port {
			continue
		}
		out = append(out, fields[9])
	}
	return out
}

// namesForInodes walks /proc looking for the processes owning these sockets.
func namesForInodes(inodes map[string]bool) []string {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}

	seen := map[string]bool{}
	var out []string
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // not a process directory
		}
		fdDir := filepath.Join("/proc", e.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue // another user's process, and we are not root
		}
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			inode, ok := strings.CutPrefix(target, "socket:[")
			if !ok {
				continue
			}
			inode = strings.TrimSuffix(inode, "]")
			if !inodes[inode] {
				continue
			}
			name := processName(pid)
			key := fmt.Sprintf("%s (pid %d)", name, pid)
			if !seen[key] {
				seen[key] = true
				out = append(out, key)
			}
			break
		}
	}
	return out
}

func processName(pid int) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)) // #nosec G304 -- pid comes from a /proc directory listing
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(b))
}
