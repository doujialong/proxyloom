package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/doujialong/proxyloom/internal/storage/jobstore"
)

type WorkerOptions struct {
	Owner            string
	Lease            time.Duration
	PollInterval     time.Duration
	Log              func(string, ...interface{})
	OnRefreshSuccess func(context.Context, string) error
}

type Worker struct {
	manager          *Manager
	jobs             *jobstore.Store
	owner            string
	lease            time.Duration
	pollInterval     time.Duration
	log              func(string, ...interface{})
	onRefreshSuccess func(context.Context, string) error
}

func NewWorker(manager *Manager, jobs *jobstore.Store, options WorkerOptions) (*Worker, error) {
	if manager == nil || jobs == nil || options.Owner == "" {
		return nil, fmt.Errorf("worker manager, job store and owner are required")
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
		manager: manager, jobs: jobs, owner: options.Owner,
		lease: options.Lease, pollInterval: options.PollInterval, log: options.Log,
		onRefreshSuccess: options.OnRefreshSuccess,
	}, nil
}

func (w *Worker) Run(ctx context.Context) error {
	recovered, err := w.jobs.RecoverExpired(ctx)
	if err != nil {
		return err
	}
	if recovered > 0 {
		w.log("recovered %d expired jobs", recovered)
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
			w.log("worker cycle failed: %v", err)
		}
		if worked {
			timer.Reset(0)
		} else {
			timer.Reset(w.pollInterval)
		}
	}
}

func (w *Worker) ProcessOne(ctx context.Context) (bool, error) {
	job, exists, err := w.jobs.Claim(ctx, w.owner, w.lease)
	if err != nil || !exists {
		return false, err
	}
	job, err = w.jobs.MarkRunning(ctx, job.ID, w.owner)
	if err != nil {
		return true, err
	}
	result, refreshErr := w.manager.Refresh(ctx, job.SourceID, job.SourceRevisionID, job.CorrelationID)
	if refreshErr != nil {
		if ctx.Err() != nil {
			return true, nil
		}
		code := "refresh_failed"
		var operation *OperationError
		if errors.As(refreshErr, &operation) {
			code = operation.Code
		}
		_, finishErr := w.jobs.Fail(ctx, job.ID, w.owner, code, boundedDetail(refreshErr))
		if finishErr != nil {
			return true, fmt.Errorf("refresh failed (%v) and job finalization failed: %w", refreshErr, finishErr)
		}
		next, scheduleErr := w.manager.NextRefreshAfterFailure(ctx, job.SourceID, job.SourceRevisionID)
		if scheduleErr != nil {
			w.log("read source %s schedule after refresh failure: %v", job.SourceID, scheduleErr)
		} else if next != nil {
			if _, enqueueErr := w.jobs.Enqueue(ctx, jobstore.EnqueueRequest{
				SourceID: job.SourceID, SourceRevisionID: job.SourceRevisionID,
				DueAt: *next, CorrelationID: "schedule-after-failure-" + job.SourceID,
			}); enqueueErr != nil {
				return true, fmt.Errorf("schedule source refresh after failure: %w", enqueueErr)
			}
		}
		return true, nil
	}
	if _, err := w.jobs.Complete(ctx, job.ID, w.owner); err != nil {
		return true, err
	}
	if result.NextRefreshAt != nil {
		_, err := w.jobs.Enqueue(ctx, jobstore.EnqueueRequest{
			SourceID: job.SourceID, SourceRevisionID: job.SourceRevisionID,
			DueAt: *result.NextRefreshAt, CorrelationID: "schedule-" + job.SourceID,
		})
		if err != nil {
			return true, fmt.Errorf("schedule next source refresh: %w", err)
		}
	}
	if result.HealthScheduleError != nil {
		w.log("health scheduling for source %s failed: %v", job.SourceID, result.HealthScheduleError)
	}
	if w.onRefreshSuccess != nil {
		if err := w.onRefreshSuccess(ctx, job.SourceID); err != nil {
			w.log("enqueue managed outputs after source %s refresh failed: %v", job.SourceID, err)
		}
	}
	return true, nil
}
