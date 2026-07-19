package aggregate

import (
	"context"
	"fmt"
	"hash/crc32"
	"strconv"
	"strings"
	"time"

	"github.com/doujialong/proxyloom/internal/storage/outputjobstore"
)

type WorkerOptions struct {
	Owner        string
	Lease        time.Duration
	PollInterval time.Duration
	Log          func(string, ...interface{})
}

type Worker struct {
	manager      *Manager
	jobs         *outputjobstore.Store
	owner        string
	lease        time.Duration
	pollInterval time.Duration
	log          func(string, ...interface{})
	templateNext map[string]templateRefreshSchedule
	templateScan time.Time
}

type templateRefreshSchedule struct {
	revision int
	due      time.Time
	failures int
}

func NewWorker(manager *Manager, jobs *outputjobstore.Store, options WorkerOptions) (*Worker, error) {
	if manager == nil || jobs == nil || strings.TrimSpace(options.Owner) == "" {
		return nil, fmt.Errorf("managed output worker dependencies are required")
	}
	if options.Lease <= 0 {
		options.Lease = 2 * time.Minute
	}
	if options.PollInterval <= 0 {
		options.PollInterval = 500 * time.Millisecond
	}
	if options.Log == nil {
		options.Log = func(string, ...interface{}) {}
	}
	return &Worker{
		manager: manager, jobs: jobs, owner: options.Owner, lease: options.Lease,
		pollInterval: options.PollInterval, log: options.Log,
		templateNext: make(map[string]templateRefreshSchedule),
	}, nil
}

func (w *Worker) Run(ctx context.Context) error {
	if recovered, err := w.jobs.RecoverExpired(ctx); err != nil {
		return err
	} else if recovered > 0 {
		w.log("recovered %d expired managed output build jobs", recovered)
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
		}
		worked, err := w.ProcessOne(ctx)
		if err != nil {
			w.log("managed output worker cycle failed: %v", err)
		}
		if worked {
			timer.Reset(0)
		} else {
			timer.Reset(w.pollInterval)
		}
	}
}

func (w *Worker) ProcessOne(ctx context.Context) (bool, error) {
	now := w.manager.now().UTC()
	if !now.Before(w.templateScan) {
		w.templateScan = now.Add(time.Second)
		worked, err := w.processOneRemoteTemplate(ctx)
		if worked || err != nil {
			return worked, err
		}
	}
	job, exists, err := w.jobs.Claim(ctx, w.owner, w.lease)
	if err != nil {
		return false, err
	}
	if !exists {
		return false, nil
	}
	if _, err := w.jobs.MarkRunning(ctx, job.ID, w.owner); err != nil {
		return true, err
	}
	if _, err := w.manager.Build(ctx, job.OutputID); err != nil {
		if ctx.Err() != nil {
			return true, nil
		}
		detail := err.Error()
		if len(detail) > 4096 {
			detail = detail[:4096]
		}
		if _, finishErr := w.jobs.Fail(ctx, job.ID, w.owner, "output_build_failed", detail); finishErr != nil {
			return true, fmt.Errorf("managed output build failed (%v) and finalization failed: %w", err, finishErr)
		}
		return true, nil
	}
	if _, err := w.jobs.Complete(ctx, job.ID, w.owner); err != nil {
		return true, err
	}
	return true, nil
}

func (w *Worker) processOneRemoteTemplate(ctx context.Context) (bool, error) {
	resources, err := w.manager.store.Resources(ctx, "template")
	if err != nil {
		return false, err
	}
	now := w.manager.now().UTC()
	var delayedError error
	for _, resource := range resources {
		config, remote, err := w.manager.store.RemoteTemplateConfig(ctx, resource)
		if err != nil {
			schedule := w.templateNext[resource.ID]
			schedule.revision = resource.RevisionNumber
			schedule.failures++
			schedule.due = now.Add(templateRetryDelay(resource.ID, schedule.failures))
			w.templateNext[resource.ID] = schedule
			delayedError = fmt.Errorf("read remote template %s: %w", resource.ID, err)
			continue
		}
		if !remote {
			continue
		}
		interval := time.Duration(config.RefreshIntervalSeconds) * time.Second
		schedule, exists := w.templateNext[resource.ID]
		if !exists || schedule.revision != resource.RevisionNumber {
			schedule = templateRefreshSchedule{revision: resource.RevisionNumber, due: resource.UpdatedAt.Add(interval)}
			w.templateNext[resource.ID] = schedule
		}
		if now.Before(schedule.due) {
			continue
		}
		updated, changed, err := w.manager.RefreshRemoteTemplate(ctx, resource.ID)
		if err != nil {
			if updated.ID != "" {
				schedule.revision = updated.RevisionNumber
			}
			schedule.failures++
			schedule.due = now.Add(templateRetryDelay(resource.ID, schedule.failures))
			w.templateNext[resource.ID] = schedule
			return true, fmt.Errorf("refresh remote template %s: %w", resource.ID, err)
		}
		if changed {
			w.templateNext[resource.ID] = templateRefreshSchedule{revision: updated.RevisionNumber, due: now.Add(interval)}
			w.log("remote template %s refreshed to revision %d", resource.ID, updated.RevisionNumber)
		} else {
			w.templateNext[resource.ID] = templateRefreshSchedule{revision: resource.RevisionNumber, due: now.Add(interval)}
		}
		return true, nil
	}
	return delayedError != nil, delayedError
}

func templateRetryDelay(templateID string, failures int) time.Duration {
	if failures < 1 {
		failures = 1
	}
	shift := failures - 1
	if shift > 4 {
		shift = 4
	}
	delay := 30 * time.Second * time.Duration(1<<shift)
	if delay > 5*time.Minute {
		delay = 5 * time.Minute
	}
	checksum := crc32.ChecksumIEEE([]byte(templateID + "/" + strconv.Itoa(failures)))
	permille := int64(checksum%401) - 200
	delay += time.Duration(int64(delay) * permille / 1000)
	if delay > 5*time.Minute {
		return 5 * time.Minute
	}
	return delay
}
