// Package enrich resolves process-context information from /proc at event time.
package enrich

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var procMemRe = regexp.MustCompile(`^/proc/\d+/mem$`)

// CWD resolves /proc/<pid>/cwd.  Returns nil on any error (process already gone, etc.).
func CWD(pid uint32) *string {
	p, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
	if err != nil {
		return nil
	}
	return &p
}

// FDPath resolves /proc/<pid>/fd/<fd> to an absolute path.  Returns "" on error.
func FDPath(pid, fd uint32) string {
	p, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, fd))
	if err != nil {
		return ""
	}
	return p
}

// ModuleName extracts a module name from an fd path (basename without .ko extension).
func ModuleName(fdPath string) string {
	base := filepath.Base(fdPath)
	return strings.TrimSuffix(base, ".ko")
}

// IsSensitiveOpenatPath returns true if the path matches one of the precise
// patterns we care about.  The in-kernel filter over-captures /proc/ opens;
// we refine that here.
func IsSensitiveOpenatPath(path string) bool {
	if procMemRe.MatchString(path) {
		return true
	}
	prefixes := []string{
		"/etc/shadow",
		"/etc/passwd",
		"/root/.ssh/",
		"/var/spool/cron/",
		"/etc/cron",
		"/etc/systemd/system/",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// IsTmpExecPath returns true if the path is under a temp dir.
func IsTmpExecPath(path string) bool {
	for _, p := range []string{"/tmp/", "/dev/shm/", "/var/tmp/"} {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// BootWall computes an approximate wall-clock time of kernel boot by subtracting
// /proc/uptime from the current time.  Used to convert ktime_ns to RFC3339.
func BootWall() time.Time {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return time.Now()
	}
	var upSec float64
	fmt.Sscanf(string(data), "%f", &upSec)
	return time.Now().Add(-time.Duration(float64(time.Second) * upSec))
}

// KtimeToWall converts a BPF ktime_ns (monotonic, ns since boot) to wall-clock time.
func KtimeToWall(boot time.Time, ktimeNs uint64) time.Time {
	return boot.Add(time.Duration(ktimeNs))
}

// DecodeOpenFlags converts an openat flags bitmask to readable strings.
func DecodeOpenFlags(flags uint32) []string {
	out := []string{}
	accmode := flags & 3
	switch accmode {
	case 0:
		out = append(out, "O_RDONLY")
	case 1:
		out = append(out, "O_WRONLY")
	case 2:
		out = append(out, "O_RDWR")
	}
	bit := func(mask uint32, name string) {
		if flags&mask != 0 {
			out = append(out, name)
		}
	}
	bit(0x40, "O_CREAT")
	bit(0x80, "O_EXCL")
	bit(0x200, "O_TRUNC")
	bit(0x400, "O_APPEND")
	bit(0x800, "O_NONBLOCK")
	bit(0x10000, "O_SYNC")
	bit(0x80000, "O_DIRECTORY")
	bit(0x100000, "O_NOFOLLOW")
	return out
}
