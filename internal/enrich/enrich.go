// Package enrich provides the boot-time clock used to convert BPF ktime to wall-clock.
package enrich

import (
	"fmt"
	"os"
	"time"
)

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
