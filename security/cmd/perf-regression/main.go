package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

const defaultThreshold = 0.30

// allocsThreshold is intentionally stricter than timing — allocation counts
// are deterministic and should not regress without deliberate cause.
const defaultAllocsThreshold = 0.10

// jitterBand is the minimum absolute delta (in the same unit) below which
// timing regressions are ignored. Small absolute changes within noise range
// should not fail the gate.
const defaultJitterBand = 0.0

var trackedMetrics = map[string][]string{
	"BenchmarkValidateJWTOnly": {"ns/op", "allocs/op"},
	"BenchmarkValidateStrict":  {"ns/op", "allocs/op"},
	"BenchmarkRefresh":         {"ns/op", "allocs/op"},
}

type sampleSet map[string]map[string][]float64

func main() {
	var (
		baselinePath    string
		candidatePath   string
		threshold       float64
		allocsThreshold float64
		jitterBand      float64
	)

	flag.StringVar(&baselinePath, "baseline", "", "path to baseline benchmark output")
	flag.StringVar(&candidatePath, "candidate", "", "path to candidate benchmark output")
	flag.Float64Var(&threshold, "threshold", defaultThreshold, "maximum allowed regression ratio for ns/op (0.30 = +30%)")
	flag.Float64Var(&allocsThreshold, "allocs-threshold", defaultAllocsThreshold, "maximum allowed regression ratio for allocs/op (0.10 = +10%)")
	flag.Float64Var(&jitterBand, "jitter-band", defaultJitterBand, "minimum absolute delta to consider (ignores noise below this)")
	flag.Parse()

	if baselinePath == "" || candidatePath == "" {
		fmt.Fprintln(os.Stderr, "-baseline and -candidate are required")
		os.Exit(2)
	}
	if threshold < 0 {
		fmt.Fprintln(os.Stderr, "-threshold must be >= 0")
		os.Exit(2)
	}

	baseline, err := parseBenchmarkFile(baselinePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse baseline: %v\n", err)
		os.Exit(1)
	}
	candidate, err := parseBenchmarkFile(candidatePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse candidate: %v\n", err)
		os.Exit(1)
	}

	var failures []string
	fmt.Println("perf regression check:")
	fmt.Println("benchmark metric baseline candidate delta threshold")

	for benchmark, metrics := range trackedMetrics {
		for _, metric := range metrics {
			baseSamples := baseline[benchmark][metric]
			candidateSamples := candidate[benchmark][metric]
			if len(baseSamples) == 0 || len(candidateSamples) == 0 {
				failures = append(failures, fmt.Sprintf("missing samples for %s %s", benchmark, metric))
				continue
			}

			baseMedian := median(baseSamples)
			candidateMedian := median(candidateSamples)
			if baseMedian <= 0 {
				failures = append(failures, fmt.Sprintf("invalid baseline median for %s %s", benchmark, metric))
				continue
			}

			delta := (candidateMedian - baseMedian) / baseMedian
			absDelta := candidateMedian - baseMedian
			if absDelta < 0 {
				absDelta = -absDelta
			}

			// Select threshold: allocs/op uses the stricter allocs threshold.
			metricThreshold := threshold
			if metric == "allocs/op" {
				metricThreshold = allocsThreshold
			}

			fmt.Printf("%s %s %.3f %.3f %+0.2f%% (limit %+0.2f%%)\n",
				benchmark, metric, baseMedian, candidateMedian, delta*100, metricThreshold*100)

			// Skip regression if the absolute delta is within jitter band
			// (only applies to timing metrics; allocs are deterministic).
			if metric == "ns/op" && jitterBand > 0 && absDelta < jitterBand {
				fmt.Printf("  (within jitter band of %.1f, skipped)\n", jitterBand)
				continue
			}

			if delta > metricThreshold {
				failures = append(failures, fmt.Sprintf("%s %s regressed by %+0.2f%% (limit %+0.2f%%)",
					benchmark, metric, delta*100, metricThreshold*100))
			}
		}
	}

	if len(failures) > 0 {
		fmt.Fprintln(os.Stderr, "performance regression threshold exceeded:")
		for _, failure := range failures {
			fmt.Fprintf(os.Stderr, "  - %s\n", failure)
		}
		os.Exit(1)
	}
}

func parseBenchmarkFile(path string) (sampleSet, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	samples := sampleSet{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "Benchmark") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		name := normalizeBenchmarkName(fields[0])
		if _, ok := trackedMetrics[name]; !ok {
			continue
		}

		if _, ok := samples[name]; !ok {
			samples[name] = map[string][]float64{}
		}

		for i := 2; i+1 < len(fields); i += 2 {
			value, err := strconv.ParseFloat(fields[i], 64)
			if err != nil {
				continue
			}
			unit := fields[i+1]
			samples[name][unit] = append(samples[name][unit], value)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return samples, nil
}

func normalizeBenchmarkName(raw string) string {
	if idx := strings.LastIndexByte(raw, '-'); idx > 0 {
		if _, err := strconv.Atoi(raw[idx+1:]); err == nil {
			return raw[:idx]
		}
	}
	return raw
}

func median(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}

	copied := make([]float64, len(values))
	copy(copied, values)
	sort.Float64s(copied)

	mid := len(copied) / 2
	if len(copied)%2 == 1 {
		return copied[mid]
	}
	return (copied[mid-1] + copied[mid]) / 2
}
