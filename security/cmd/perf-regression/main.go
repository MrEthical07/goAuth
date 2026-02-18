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

var trackedMetrics = map[string][]string{
	"BenchmarkValidateJWTOnly": {"ns/op", "allocs/op"},
	"BenchmarkValidateStrict":  {"ns/op", "allocs/op"},
	"BenchmarkRefresh":         {"ns/op"},
}

type sampleSet map[string]map[string][]float64

func main() {
	var (
		baselinePath  string
		candidatePath string
		threshold     float64
	)

	flag.StringVar(&baselinePath, "baseline", "", "path to baseline benchmark output")
	flag.StringVar(&candidatePath, "candidate", "", "path to candidate benchmark output")
	flag.Float64Var(&threshold, "threshold", defaultThreshold, "maximum allowed regression ratio (0.30 = +30%)")
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
	fmt.Println("benchmark metric baseline candidate delta")

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
			fmt.Printf("%s %s %.3f %.3f %+0.2f%%\n", benchmark, metric, baseMedian, candidateMedian, delta*100)
			if delta > threshold {
				failures = append(failures, fmt.Sprintf("%s %s regressed by %+0.2f%% (limit %+0.2f%%)", benchmark, metric, delta*100, threshold*100))
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
