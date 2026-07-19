package app

import (
	"context"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	singboxexecutor "github.com/doujialong/proxyloom/internal/executor/singbox"
	"github.com/doujialong/proxyloom/internal/storage/blobstore"
	"github.com/doujialong/proxyloom/internal/storage/healthstore"
)

var defaultProbeTargets = []singboxexecutor.Target{
	{ID: "cloudflare-generate-204", URL: "https://cp.cloudflare.com/generate_204", ExpectedStatus: http.StatusNoContent},
	{ID: "google-generate-204", URL: "https://www.gstatic.com/generate_204", ExpectedStatus: http.StatusNoContent},
}

type HealthWorkerOptions struct {
	Owner            string
	Concurrency      int
	PollInterval     time.Duration
	Lease            time.Duration
	ECHExecutor      *singboxexecutor.Validator
	Log              func(string, ...interface{})
	OnFilterBoundary func(context.Context, string) error
}

type HealthWorker struct {
	store            *healthstore.Store
	blobs            *blobstore.Store
	executor         *singboxexecutor.Validator
	echExecutor      *singboxexecutor.Validator
	owner            string
	concurrency      int
	pollInterval     time.Duration
	lease            time.Duration
	log              func(string, ...interface{})
	controlMu        sync.Mutex
	onFilterBoundary func(context.Context, string) error
}

func NewHealthWorker(store *healthstore.Store, blobs *blobstore.Store, executor *singboxexecutor.Validator, options HealthWorkerOptions) (*HealthWorker, error) {
	if store == nil || blobs == nil || executor == nil {
		return nil, fmt.Errorf("health worker dependencies are required")
	}
	if options.Owner == "" {
		return nil, fmt.Errorf("health worker owner is required")
	}
	if options.Concurrency == 0 {
		options.Concurrency = 4
	}
	if options.Concurrency < 1 || options.Concurrency > 4 {
		return nil, fmt.Errorf("health executor concurrency must be between 1 and 4")
	}
	if options.PollInterval <= 0 {
		options.PollInterval = time.Second
	}
	if options.Lease <= 0 {
		options.Lease = healthstore.DefaultLease
	}
	if options.Log == nil {
		options.Log = func(string, ...interface{}) {}
	}
	return &HealthWorker{
		store: store, blobs: blobs, executor: executor, echExecutor: options.ECHExecutor, owner: options.Owner,
		concurrency: options.Concurrency, pollInterval: options.PollInterval,
		lease: options.Lease, log: options.Log,
		onFilterBoundary: options.OnFilterBoundary,
	}, nil
}

func (w *HealthWorker) Run(ctx context.Context) error {
	if _, err := w.store.RecoverExpired(ctx); err != nil {
		return err
	}
	errChannel := make(chan error, w.concurrency)
	var group sync.WaitGroup
	for index := 0; index < w.concurrency; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			owner := fmt.Sprintf("%s-%d", w.owner, index+1)
			if err := w.runOne(ctx, owner); err != nil {
				errChannel <- err
			}
		}(index)
	}
	done := make(chan struct{})
	go func() { group.Wait(); close(done) }()
	select {
	case <-ctx.Done():
		<-done
		return nil
	case err := <-errChannel:
		return err
	case <-done:
		return nil
	}
}

func (w *HealthWorker) runOne(ctx context.Context, owner string) error {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
		}
		worked, err := w.ProcessOne(ctx, owner)
		if err != nil {
			w.log("health worker cycle failed: %v", err)
		}
		if worked {
			timer.Reset(0)
		} else {
			timer.Reset(w.pollInterval)
		}
	}
}

func (w *HealthWorker) ProcessOne(ctx context.Context, owner string) (bool, error) {
	controlsPresent, controlsAvailable, err := w.store.ControlsAvailable(ctx)
	if err != nil {
		return false, err
	}
	if !controlsPresent {
		w.controlMu.Lock()
		controlsPresent, controlsAvailable, err = w.store.ControlsAvailable(ctx)
		if err == nil && !controlsPresent {
			controlsAvailable, err = w.refreshControls(ctx)
		}
		w.controlMu.Unlock()
		if err != nil {
			return false, err
		}
	}
	item, exists, err := w.store.Claim(ctx, owner, w.lease)
	if err != nil || !exists {
		return false, err
	}
	canonical, err := w.loadCanonical(ctx, item)
	if err != nil {
		_, completeErr := w.store.Complete(ctx, item, owner, healthstore.ProbeResult{
			Class: healthstore.ResultExecutorCrash, Success: false, NodeAttributable: false,
			Total: 0, DiagnosticCode: "canonical_node_unavailable",
			ExecutorID: singboxexecutor.ExecutorID, ExecutorVersion: w.executor.Version(),
		})
		if completeErr != nil {
			return true, fmt.Errorf("load canonical node (%v) and complete health item: %w", err, completeErr)
		}
		return true, nil
	}
	executor := w.executor
	if singboxexecutor.ContainsECH(canonical) {
		executor = w.echExecutor
	}
	if executor == nil {
		state, completeErr := w.store.Complete(ctx, item, owner, healthstore.ProbeResult{
			Class: healthstore.ResultUnsupported, Success: false, NodeAttributable: false,
			Total: 0, DiagnosticCode: "compatible_executor_unavailable",
			ExecutorID: singboxexecutor.ExecutorID, ExecutorVersion: w.executor.Version(),
		})
		if completeErr != nil {
			return true, completeErr
		}
		if w.onFilterBoundary != nil && healthFilterExcluded(item.State, item.RecoveryStep) != healthFilterExcluded(state.State, state.RecoveryStep) {
			if boundaryErr := w.onFilterBoundary(ctx, item.SourceID); boundaryErr != nil {
				w.log("enqueue unsupported health-boundary rebuild for source %s failed: %v", item.SourceID, boundaryErr)
			}
		}
		return true, nil
	}
	primaryIndex := stableTargetIndex(item.NodeOccurrenceID, len(defaultProbeTargets))
	if item.RecoveryStep == 1 {
		primaryIndex = (primaryIndex + 1) % len(defaultProbeTargets)
	}
	primary := defaultProbeTargets[primaryIndex]
	probe := executor.Probe(ctx, canonical, primary)
	final := probe
	finalTarget := primary
	if !probe.Success {
		secondary := defaultProbeTargets[(primaryIndex+1)%len(defaultProbeTargets)]
		confirmed := executor.Probe(ctx, canonical, secondary)
		final, finalTarget = confirmed, secondary
		if confirmed.Success {
			final = confirmed
		}
	}
	class, success, nodeAttributable := normalizeProbeOutcome(final, controlsAvailable)
	state, err := w.store.Complete(ctx, item, owner, healthstore.ProbeResult{
		Class: class, Success: success, NodeAttributable: nodeAttributable,
		TargetID: finalTarget.ID, HTTPStatus: final.HTTPStatus, Total: final.Total,
		DiagnosticCode: final.DiagnosticCode,
		ExecutorID:     singboxexecutor.ExecutorID, ExecutorVersion: executor.Version(),
	})
	if err != nil {
		return true, err
	}
	if w.onFilterBoundary != nil && healthFilterExcluded(item.State, item.RecoveryStep) != healthFilterExcluded(state.State, state.RecoveryStep) {
		if err := w.onFilterBoundary(ctx, item.SourceID); err != nil {
			w.log("enqueue health-boundary rebuild for source %s failed: %v", item.SourceID, err)
		}
	}
	return true, nil
}

func normalizeProbeOutcome(result singboxexecutor.ProbeResult, controlsAvailable bool) (healthstore.ResultClass, bool, bool) {
	class := healthstore.ResultClass(result.Class)
	if !controlsAvailable {
		return healthstore.ResultTargetFailure, false, false
	}
	return class, result.Success, !result.Success && isNodeAttributableClass(class)
}

func (w *HealthWorker) loadCanonical(ctx context.Context, item healthstore.ProbeItem) ([]byte, error) {
	blobID := item.CanonicalBlobID
	if item.FormatID == "sing-box-json" {
		blobID = item.RawBlobID
	}
	if blobID == "" {
		return nil, fmt.Errorf("node has no executable canonical representation")
	}
	content, record, err := w.blobs.Get(ctx, blobID)
	if err != nil {
		return nil, err
	}
	if item.FormatID == "sing-box-json" {
		if record.Kind != "raw_node" {
			return nil, fmt.Errorf("sing-box node references a non-raw blob")
		}
		wrapped := make([]byte, 0, len(content)+2)
		wrapped = append(wrapped, '[')
		wrapped = append(wrapped, content...)
		return append(wrapped, ']'), nil
	}
	if record.Kind != "canonical_node" {
		return nil, fmt.Errorf("converted node references a non-canonical blob")
	}
	return content, nil
}

func (w *HealthWorker) refreshControls(ctx context.Context) (bool, error) {
	available := false
	for _, target := range defaultProbeTargets {
		result := directControlProbe(ctx, target)
		if result.Success {
			available = true
		}
		if err := w.store.RecordControl(ctx, target.ID, result); err != nil {
			return false, err
		}
	}
	return available, nil
}

func directControlProbe(ctx context.Context, target singboxexecutor.Target) healthstore.ProbeResult {
	started := time.Now()
	probeContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	transport := &http.Transport{
		Proxy: nil, DisableKeepAlives: true,
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSHandshakeTimeout: 5 * time.Second, ForceAttemptHTTP2: false,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	request, err := http.NewRequestWithContext(probeContext, http.MethodGet, target.URL, nil)
	if err != nil {
		return healthstore.ProbeResult{Class: healthstore.ResultTargetFailure, Total: time.Since(started), ExecutorID: "direct-control", ExecutorVersion: "v1"}
	}
	request.Header.Set("User-Agent", "Mozilla/5.0")
	response, err := client.Do(request)
	if err != nil {
		class := healthstore.ResultTargetFailure
		if networkError, ok := err.(net.Error); ok && networkError.Timeout() {
			class = healthstore.ResultConnectTimeout
		}
		return healthstore.ProbeResult{Class: class, Total: time.Since(started), ExecutorID: "direct-control", ExecutorVersion: "v1"}
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1025))
	status := response.StatusCode
	if status != target.ExpectedStatus {
		return healthstore.ProbeResult{
			Class: healthstore.ResultUnexpectedStatus, HTTPStatus: &status,
			Total: time.Since(started), ExecutorID: "direct-control", ExecutorVersion: "v1",
		}
	}
	return healthstore.ProbeResult{
		Class: healthstore.ResultSuccess, Success: true, HTTPStatus: &status,
		Total: time.Since(started), ExecutorID: "direct-control", ExecutorVersion: "v1",
	}
}

func stableTargetIndex(value string, count int) int {
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(value))
	return int(hash.Sum32() % uint32(count))
}

func isNodeAttributableClass(class healthstore.ResultClass) bool {
	switch class {
	case healthstore.ResultDNSFailure, healthstore.ResultConnectTimeout, healthstore.ResultConnectRefused,
		healthstore.ResultAuthFailure, healthstore.ResultTLSFailure, healthstore.ResultProtocolFailure,
		healthstore.ResultUnexpectedStatus:
		return true
	default:
		return false
	}
}

func healthFilterExcluded(state healthstore.State, recoveryStep int) bool {
	return state == healthstore.StateUnhealthy || recoveryStep == 1
}

func sanitizeHealthDiagnostic(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 128 {
		value = value[:128]
	}
	return value
}
