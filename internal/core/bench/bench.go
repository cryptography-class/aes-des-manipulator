package bench

import (
	"fmt"
	"os"
	"runtime"
	"text/tabwriter"
	"time"
)

// bToMb converts bytes to megabytes.
func bToMb(b uint64) uint64 {
	return b / 1024 / 1024
}

// MeasurePerformance measures performance metrics.
// It should be called in a defer statement.
func MeasurePerformance() func() {
	start := time.Now()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	tab := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)

	return func() {
		var after runtime.MemStats
		runtime.ReadMemStats(&after)

		_, _ = fmt.Fprintf(tab, "\nPerformance\n")
		_, _ = fmt.Fprintf(tab, "Time\t%s\n", time.Since(start))
		_, _ = fmt.Fprintf(tab, "Alloc (now)\t%d MB\n", bToMb(after.Alloc))
		_, _ = fmt.Fprintf(tab, "TotalAlloc (delta)\t%d MB\n", bToMb(after.TotalAlloc-before.TotalAlloc))
		_, _ = fmt.Fprintf(tab, "Mallocs (delta)\t%d\n", after.Mallocs-before.Mallocs)
		_, _ = fmt.Fprintf(tab, "Sys\t%d MB\n", bToMb(after.Sys))
		_, _ = fmt.Fprintf(tab, "NumGC (delta)\t%d\n", after.NumGC-before.NumGC)
		_, _ = fmt.Fprintf(tab, "GC pause total (delta)\t%s\n",
			time.Duration(after.PauseTotalNs-before.PauseTotalNs))
		_, _ = fmt.Fprintf(tab, "GC CPU fraction\t%.4f\n", after.GCCPUFraction)
		_ = tab.Flush()
	}
}
