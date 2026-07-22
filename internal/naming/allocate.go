package naming

import (
	"fmt"
	"sort"
	"time"
)

const (
	AlgorithmVersion = "name-suffix-v2"
	DefaultRetention = 30 * 24 * time.Hour
)

type Candidate struct {
	OccurrenceID     string
	BaseName         string
	StableKey        string
	CandidateOrdinal int
}

type Allocation struct {
	OccurrenceID  string
	BaseName      string
	FinalName     string
	Suffix        int
	Locked        bool
	Active        bool
	LastSeenAt    time.Time
	ReservedUntil time.Time
	Version       string
}

type SnapshotItem struct {
	OccurrenceID     string
	BaseName         string
	FinalName        string
	Suffix           int
	CandidateOrdinal int
}

type Options struct {
	Now           time.Time
	Retention     time.Duration
	ReservedNames []string
}

type Result struct {
	Allocations []Allocation
	Snapshot    []SnapshotItem
}

func Allocate(existing []Allocation, candidates []Candidate, options Options) (Result, error) {
	if options.Now.IsZero() {
		return Result{}, fmt.Errorf("allocation time is required")
	}
	if options.Retention <= 0 {
		options.Retention = DefaultRetention
	}

	activeCandidates := make(map[string]Candidate, len(candidates))
	ordinals := make(map[int]struct{}, len(candidates))
	for _, candidate := range candidates {
		if candidate.OccurrenceID == "" {
			return Result{}, fmt.Errorf("candidate occurrence ID is required")
		}
		if candidate.BaseName == "" {
			return Result{}, fmt.Errorf("candidate %q has an empty base name", candidate.OccurrenceID)
		}
		if candidate.StableKey == "" {
			return Result{}, fmt.Errorf("candidate %q has an empty stable key", candidate.OccurrenceID)
		}
		if _, duplicate := activeCandidates[candidate.OccurrenceID]; duplicate {
			return Result{}, fmt.Errorf("duplicate candidate occurrence ID %q", candidate.OccurrenceID)
		}
		if _, duplicate := ordinals[candidate.CandidateOrdinal]; duplicate {
			return Result{}, fmt.Errorf("duplicate candidate ordinal %d", candidate.CandidateOrdinal)
		}
		activeCandidates[candidate.OccurrenceID] = candidate
		ordinals[candidate.CandidateOrdinal] = struct{}{}
	}

	reserved := make(map[string]struct{}, len(options.ReservedNames))
	for _, name := range options.ReservedNames {
		if name == "" {
			continue
		}
		reserved[name] = struct{}{}
	}
	protectedBaseNames := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		protectedBaseNames[candidate.BaseName] = struct{}{}
	}

	allocationsByOccurrence := make(map[string]Allocation, len(existing)+len(candidates))
	occupied := make(map[string]string, len(existing)+len(reserved))
	for name := range reserved {
		occupied[name] = "reserved"
	}
	for _, allocation := range existing {
		if allocation.OccurrenceID == "" || allocation.FinalName == "" || allocation.Suffix < 1 {
			return Result{}, fmt.Errorf("invalid existing allocation for %q", allocation.OccurrenceID)
		}
		_, present := activeCandidates[allocation.OccurrenceID]
		if !allocation.Active && !options.Now.Before(allocation.ReservedUntil) {
			continue
		}
		if _, duplicate := allocationsByOccurrence[allocation.OccurrenceID]; duplicate {
			return Result{}, fmt.Errorf("duplicate allocation for occurrence %q", allocation.OccurrenceID)
		}
		if owner, conflict := occupied[allocation.FinalName]; conflict {
			if owner == "reserved" && !allocation.Locked {
				continue
			}
			return Result{}, fmt.Errorf("allocation name %q conflicts with %s", allocation.FinalName, owner)
		}
		if present {
			if !allocation.Active {
				allocation.LastSeenAt = options.Now
			}
			allocation.Active = true
			allocation.ReservedUntil = time.Time{}
		} else if allocation.Active {
			allocation.Active = false
			allocation.ReservedUntil = options.Now.Add(options.Retention)
		}
		allocation.Version = AlgorithmVersion
		allocationsByOccurrence[allocation.OccurrenceID] = allocation
		occupied[allocation.FinalName] = allocation.OccurrenceID
	}

	newCandidates := make([]Candidate, 0)
	for _, candidate := range candidates {
		if _, exists := allocationsByOccurrence[candidate.OccurrenceID]; !exists {
			newCandidates = append(newCandidates, candidate)
		}
	}
	sort.SliceStable(newCandidates, func(i, j int) bool {
		if newCandidates[i].BaseName != newCandidates[j].BaseName {
			return newCandidates[i].BaseName < newCandidates[j].BaseName
		}
		if newCandidates[i].StableKey != newCandidates[j].StableKey {
			return newCandidates[i].StableKey < newCandidates[j].StableKey
		}
		return newCandidates[i].OccurrenceID < newCandidates[j].OccurrenceID
	})
	nextSuffixByBase := make(map[string]int)
	for _, candidate := range newCandidates {
		startSuffix := nextSuffixByBase[candidate.BaseName]
		if startSuffix < 1 {
			startSuffix = 1
		}
		suffix, finalName := firstAvailableName(candidate.BaseName, occupied, protectedBaseNames, startSuffix)
		nextSuffixByBase[candidate.BaseName] = suffix + 1
		allocation := Allocation{
			OccurrenceID: candidate.OccurrenceID,
			BaseName:     candidate.BaseName,
			FinalName:    finalName,
			Suffix:       suffix,
			Active:       true,
			LastSeenAt:   options.Now,
			Version:      AlgorithmVersion,
		}
		allocationsByOccurrence[candidate.OccurrenceID] = allocation
		occupied[finalName] = candidate.OccurrenceID
	}

	snapshot := make([]SnapshotItem, 0, len(candidates))
	for _, candidate := range candidates {
		allocation := allocationsByOccurrence[candidate.OccurrenceID]
		snapshot = append(snapshot, SnapshotItem{
			OccurrenceID:     candidate.OccurrenceID,
			BaseName:         allocation.BaseName,
			FinalName:        allocation.FinalName,
			Suffix:           allocation.Suffix,
			CandidateOrdinal: candidate.CandidateOrdinal,
		})
	}
	sort.SliceStable(snapshot, func(i, j int) bool {
		return snapshot[i].CandidateOrdinal < snapshot[j].CandidateOrdinal
	})

	allocations := make([]Allocation, 0, len(allocationsByOccurrence))
	for _, allocation := range allocationsByOccurrence {
		allocations = append(allocations, allocation)
	}
	sort.SliceStable(allocations, func(i, j int) bool {
		return allocations[i].OccurrenceID < allocations[j].OccurrenceID
	})
	return Result{Allocations: allocations, Snapshot: snapshot}, nil
}

func firstAvailableName(baseName string, occupied map[string]string, protectedBaseNames map[string]struct{}, startSuffix int) (int, string) {
	for suffix := startSuffix; ; suffix++ {
		name := baseName
		if suffix > 1 {
			name = fmt.Sprintf("%s #%d", baseName, suffix)
			if _, protected := protectedBaseNames[name]; protected {
				continue
			}
		}
		if _, exists := occupied[name]; !exists {
			return suffix, name
		}
	}
}
