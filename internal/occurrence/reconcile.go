package occurrence

import (
	"fmt"
	"sort"
	"time"

	"github.com/doujialong/proxyloom/internal/identity"
)

const (
	AlgorithmVersion = "occurrence-v1"
	DefaultRetention = 30 * 24 * time.Hour
)

type State string

const (
	StatePresent State = "present"
	StateAbsent  State = "absent"
	StateRetired State = "retired"
)

type MatchMethod string

const (
	MatchFingerprintUnique MatchMethod = "fingerprint_unique"
	MatchPath              MatchMethod = "path"
	MatchDuplicateSlot     MatchMethod = "duplicate_slot"
	MatchAuxiliaryUnique   MatchMethod = "auxiliary_unique"
	MatchNew               MatchMethod = "new"
	MatchAmbiguousNew      MatchMethod = "ambiguous_new"
)

type Candidate struct {
	Ordinal        int
	Fingerprint    identity.Fingerprint
	ExtractionPath string
	ProtocolID     string
	OriginalName   string
}

type Occurrence struct {
	ID               string
	Fingerprint      identity.Fingerprint
	ExtractionPath   string
	ProtocolID       string
	OriginalName     string
	State            State
	DuplicateSlot    int
	CreatedAt        time.Time
	LastSeenAt       time.Time
	AbsentSince      *time.Time
	RetainUntil      *time.Time
	AlgorithmVersion string
}

type Link struct {
	CandidateOrdinal int
	OccurrenceID     string
	Method           MatchMethod
}

type Options struct {
	Now       time.Time
	Retention time.Duration
	NewID     func() string
}

type Result struct {
	Occurrences []Occurrence
	Links       []Link
}

type match struct {
	occurrence int
	method     MatchMethod
}

type auxiliaryKey struct {
	protocolID     string
	originalName   string
	extractionPath string
}

type duplicateSlotState struct {
	counts map[int]int
	next   int
}

type duplicateSlotAllocator map[string]*duplicateSlotState

func Reconcile(existing []Occurrence, candidates []Candidate, options Options) (Result, error) {
	if options.Now.IsZero() {
		return Result{}, fmt.Errorf("reconcile time is required")
	}
	if options.Retention <= 0 {
		options.Retention = DefaultRetention
	}
	if options.NewID == nil {
		return Result{}, fmt.Errorf("occurrence ID generator is required")
	}

	occurrences := append([]Occurrence(nil), existing...)
	knownIDs := make(map[string]struct{}, len(occurrences))
	for i := range occurrences {
		if occurrences[i].ID == "" {
			return Result{}, fmt.Errorf("existing occurrence has an empty ID")
		}
		if _, duplicate := knownIDs[occurrences[i].ID]; duplicate {
			return Result{}, fmt.Errorf("duplicate occurrence ID %q", occurrences[i].ID)
		}
		knownIDs[occurrences[i].ID] = struct{}{}
		if occurrences[i].State == StateAbsent && occurrences[i].RetainUntil != nil && !options.Now.Before(*occurrences[i].RetainUntil) {
			occurrences[i].State = StateRetired
		}
	}

	orderedCandidates := make([]int, len(candidates))
	for i := range candidates {
		orderedCandidates[i] = i
	}
	sort.SliceStable(orderedCandidates, func(i, j int) bool {
		left := candidates[orderedCandidates[i]]
		right := candidates[orderedCandidates[j]]
		if left.Ordinal != right.Ordinal {
			return left.Ordinal < right.Ordinal
		}
		return orderedCandidates[i] < orderedCandidates[j]
	})
	for i := 1; i < len(orderedCandidates); i++ {
		if candidates[orderedCandidates[i-1]].Ordinal == candidates[orderedCandidates[i]].Ordinal {
			return Result{}, fmt.Errorf("duplicate candidate ordinal %d", candidates[orderedCandidates[i]].Ordinal)
		}
	}

	matches := make(map[int]match, len(candidates))
	usedOccurrences := make(map[int]bool, len(occurrences))
	candidateFingerprintKeys := make([]string, len(candidates))
	fingerprintGroups := make(map[string][]int)
	for _, candidateIndex := range orderedCandidates {
		key := candidates[candidateIndex].Fingerprint.MatchKey()
		candidateFingerprintKeys[candidateIndex] = key
		fingerprintGroups[key] = append(fingerprintGroups[key], candidateIndex)
	}
	occurrenceFingerprintGroups := make(map[string][]int)
	for occurrenceIndex := range occurrences {
		if occurrences[occurrenceIndex].State == StateRetired {
			continue
		}
		key := occurrences[occurrenceIndex].Fingerprint.MatchKey()
		occurrenceFingerprintGroups[key] = append(occurrenceFingerprintGroups[key], occurrenceIndex)
	}
	for key := range occurrenceFingerprintGroups {
		sortOccurrenceIndexes(occurrenceFingerprintGroups[key], occurrences)
	}

	groupKeys := make([]string, 0, len(fingerprintGroups))
	for key := range fingerprintGroups {
		groupKeys = append(groupKeys, key)
	}
	sort.Strings(groupKeys)
	for _, key := range groupKeys {
		candidateIndexes := fingerprintGroups[key]
		occurrenceIndexes := occurrenceFingerprintGroups[key]
		if len(candidateIndexes) == 1 && len(occurrenceIndexes) == 1 {
			assignMatch(matches, usedOccurrences, candidateIndexes[0], occurrenceIndexes[0], MatchFingerprintUnique)
			continue
		}

		occurrencesByPath := make(map[string][]int)
		for _, occurrenceIndex := range occurrenceIndexes {
			path := occurrences[occurrenceIndex].ExtractionPath
			occurrencesByPath[path] = append(occurrencesByPath[path], occurrenceIndex)
		}
		pathCursors := make(map[string]int, len(occurrencesByPath))
		for _, candidateIndex := range candidateIndexes {
			path := candidates[candidateIndex].ExtractionPath
			pathMatches := occurrencesByPath[path]
			cursor := pathCursors[path]
			if cursor < len(pathMatches) {
				assignMatch(matches, usedOccurrences, candidateIndex, pathMatches[cursor], MatchPath)
				pathCursors[path] = cursor + 1
			}
		}

		remainingCandidates := unmatchedCandidates(candidateIndexes, matches)
		remainingOccurrences := unusedOccurrences(occurrenceIndexes, usedOccurrences)
		sortOccurrenceIndexes(remainingOccurrences, occurrences)
		for i := 0; i < len(remainingCandidates) && i < len(remainingOccurrences); i++ {
			assignMatch(matches, usedOccurrences, remainingCandidates[i], remainingOccurrences[i], MatchDuplicateSlot)
		}
	}

	unmatchedByAuxiliary := make(map[auxiliaryKey][]int)
	for _, candidateIndex := range orderedCandidates {
		if _, alreadyMatched := matches[candidateIndex]; alreadyMatched {
			continue
		}
		key := candidateAuxiliaryKey(candidates[candidateIndex])
		unmatchedByAuxiliary[key] = append(unmatchedByAuxiliary[key], candidateIndex)
	}
	unusedByAuxiliary := make(map[auxiliaryKey][]int)
	for occurrenceIndex := range occurrences {
		if usedOccurrences[occurrenceIndex] || occurrences[occurrenceIndex].State == StateRetired {
			continue
		}
		key := occurrenceAuxiliaryKey(occurrences[occurrenceIndex])
		unusedByAuxiliary[key] = append(unusedByAuxiliary[key], occurrenceIndex)
	}

	ambiguous := make(map[int]bool)
	for key, candidateIndexes := range unmatchedByAuxiliary {
		occurrenceIndexes := unusedByAuxiliary[key]
		if len(candidateIndexes) == 1 && len(occurrenceIndexes) == 1 {
			assignMatch(matches, usedOccurrences, candidateIndexes[0], occurrenceIndexes[0], MatchAuxiliaryUnique)
			continue
		}
		if len(occurrenceIndexes) > 0 {
			for _, candidateIndex := range candidateIndexes {
				ambiguous[candidateIndex] = true
			}
		}
	}

	slots := newDuplicateSlotAllocator(occurrences)
	for _, candidateIndex := range orderedCandidates {
		candidate := candidates[candidateIndex]
		if matched, exists := matches[candidateIndex]; exists {
			occurrence := &occurrences[matched.occurrence]
			oldFingerprintKey := occurrence.Fingerprint.MatchKey()
			newFingerprintKey := candidateFingerprintKeys[candidateIndex]
			fingerprintChanged := oldFingerprintKey != newFingerprintKey
			occurrence.Fingerprint = candidate.Fingerprint
			occurrence.ExtractionPath = candidate.ExtractionPath
			occurrence.ProtocolID = candidate.ProtocolID
			occurrence.OriginalName = candidate.OriginalName
			occurrence.State = StatePresent
			occurrence.LastSeenAt = options.Now
			occurrence.AbsentSince = nil
			occurrence.RetainUntil = nil
			occurrence.AlgorithmVersion = AlgorithmVersion
			if fingerprintChanged {
				slots.release(oldFingerprintKey, occurrence.DuplicateSlot)
				occurrence.DuplicateSlot = slots.allocate(newFingerprintKey)
			}
			continue
		}

		id := options.NewID()
		if id == "" {
			return Result{}, fmt.Errorf("occurrence ID generator returned an empty ID")
		}
		if _, duplicate := knownIDs[id]; duplicate {
			return Result{}, fmt.Errorf("occurrence ID generator returned duplicate ID %q", id)
		}
		knownIDs[id] = struct{}{}
		method := MatchNew
		if ambiguous[candidateIndex] {
			method = MatchAmbiguousNew
		}
		occurrences = append(occurrences, Occurrence{
			ID:               id,
			Fingerprint:      candidate.Fingerprint,
			ExtractionPath:   candidate.ExtractionPath,
			ProtocolID:       candidate.ProtocolID,
			OriginalName:     candidate.OriginalName,
			State:            StatePresent,
			DuplicateSlot:    slots.allocate(candidateFingerprintKeys[candidateIndex]),
			CreatedAt:        options.Now,
			LastSeenAt:       options.Now,
			AlgorithmVersion: AlgorithmVersion,
		})
		matches[candidateIndex] = match{occurrence: len(occurrences) - 1, method: method}
		usedOccurrences[len(occurrences)-1] = true
	}

	for index := range occurrences {
		if usedOccurrences[index] || occurrences[index].State == StateRetired {
			continue
		}
		if occurrences[index].State != StateAbsent {
			absentSince := options.Now
			retainUntil := options.Now.Add(options.Retention)
			occurrences[index].AbsentSince = &absentSince
			occurrences[index].RetainUntil = &retainUntil
		}
		occurrences[index].State = StateAbsent
	}

	links := make([]Link, 0, len(candidates))
	for _, candidateIndex := range orderedCandidates {
		matched := matches[candidateIndex]
		links = append(links, Link{
			CandidateOrdinal: candidates[candidateIndex].Ordinal,
			OccurrenceID:     occurrences[matched.occurrence].ID,
			Method:           matched.method,
		})
	}
	return Result{Occurrences: occurrences, Links: links}, nil
}

func candidateAuxiliaryKey(candidate Candidate) auxiliaryKey {
	return auxiliaryKey{
		protocolID:     candidate.ProtocolID,
		originalName:   candidate.OriginalName,
		extractionPath: candidate.ExtractionPath,
	}
}

func occurrenceAuxiliaryKey(occurrence Occurrence) auxiliaryKey {
	return auxiliaryKey{
		protocolID:     occurrence.ProtocolID,
		originalName:   occurrence.OriginalName,
		extractionPath: occurrence.ExtractionPath,
	}
}

func assignMatch(matches map[int]match, used map[int]bool, candidate, occurrence int, method MatchMethod) {
	matches[candidate] = match{occurrence: occurrence, method: method}
	used[occurrence] = true
}

func unmatchedCandidates(indexes []int, matches map[int]match) []int {
	remaining := make([]int, 0, len(indexes))
	for _, index := range indexes {
		if _, matched := matches[index]; !matched {
			remaining = append(remaining, index)
		}
	}
	return remaining
}

func unusedOccurrences(indexes []int, used map[int]bool) []int {
	remaining := make([]int, 0, len(indexes))
	for _, index := range indexes {
		if !used[index] {
			remaining = append(remaining, index)
		}
	}
	return remaining
}

func sortOccurrenceIndexes(indexes []int, occurrences []Occurrence) {
	sort.SliceStable(indexes, func(i, j int) bool {
		left := occurrences[indexes[i]]
		right := occurrences[indexes[j]]
		if !left.CreatedAt.Equal(right.CreatedAt) {
			return left.CreatedAt.Before(right.CreatedAt)
		}
		return left.ID < right.ID
	})
}

func newDuplicateSlotAllocator(occurrences []Occurrence) duplicateSlotAllocator {
	allocator := make(duplicateSlotAllocator)
	for _, occurrence := range occurrences {
		if occurrence.State == StateRetired || occurrence.DuplicateSlot < 1 {
			continue
		}
		key := occurrence.Fingerprint.MatchKey()
		state := allocator.state(key)
		state.counts[occurrence.DuplicateSlot]++
	}
	return allocator
}

func (allocator duplicateSlotAllocator) state(key string) *duplicateSlotState {
	state, exists := allocator[key]
	if exists {
		return state
	}
	state = &duplicateSlotState{counts: make(map[int]int), next: 1}
	allocator[key] = state
	return state
}

func (allocator duplicateSlotAllocator) allocate(key string) int {
	state := allocator.state(key)
	for state.counts[state.next] > 0 {
		state.next++
	}
	slot := state.next
	state.counts[slot]++
	state.next++
	return slot
}

func (allocator duplicateSlotAllocator) release(key string, slot int) {
	if slot < 1 {
		return
	}
	state, exists := allocator[key]
	if !exists || state.counts[slot] == 0 {
		return
	}
	state.counts[slot]--
	if state.counts[slot] == 0 && slot < state.next {
		state.next = slot
	}
}
