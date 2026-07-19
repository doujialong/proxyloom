package service

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/doujialong/proxyloom/internal/aggregate"
	"github.com/doujialong/proxyloom/internal/app"
	"github.com/doujialong/proxyloom/internal/auth"
	"github.com/doujialong/proxyloom/internal/crypto/keyring"
	"github.com/doujialong/proxyloom/internal/crypto/masterkey"
	singboxexecutor "github.com/doujialong/proxyloom/internal/executor/singbox"
	"github.com/doujialong/proxyloom/internal/httpapi"
	"github.com/doujialong/proxyloom/internal/managedbackup"
	"github.com/doujialong/proxyloom/internal/storage/artifactstore"
	"github.com/doujialong/proxyloom/internal/storage/blobstore"
	"github.com/doujialong/proxyloom/internal/storage/healthstore"
	"github.com/doujialong/proxyloom/internal/storage/jobstore"
	"github.com/doujialong/proxyloom/internal/storage/outputjobstore"
	"github.com/doujialong/proxyloom/internal/storage/outputstore"
	"github.com/doujialong/proxyloom/internal/storage/sourcestore"
	storagesqlite "github.com/doujialong/proxyloom/internal/storage/sqlite"
	"github.com/google/uuid"
)

type Config struct {
	DataDir               string
	MasterKeyPath         string
	AdminTokenPath        string
	Listen                string
	Development           bool
	SingBoxPath           string
	SingBox13Path         string
	PublicOrigin          string
	SecureCookie          bool
	RemoteTemplateFetcher aggregate.RemoteFetcher
}

type Service struct {
	config       Config
	runtimeLock  *os.File
	sqlite       *storagesqlite.Store
	keys         ioCloser
	admin        *auth.Token
	sessions     *auth.Store
	jobs         *jobstore.Store
	worker       *app.Worker
	outputWorker *aggregate.Worker
	healthWorker *app.HealthWorker
	healthStore  *healthstore.Store
	outputs      *outputstore.Store
	outputJobs   *outputjobstore.Store
	aggregate    *aggregate.Manager
	api          *httpapi.Server
	httpServer   *http.Server
}

type ioCloser interface {
	Close()
}

type maintenanceRuntime struct {
	sqlite   *storagesqlite.Store
	keys     *keyring.Ring
	sessions *auth.Store
}

func Open(ctx context.Context, config Config) (*Service, error) {
	if config.DataDir == "" || config.MasterKeyPath == "" || config.AdminTokenPath == "" {
		return nil, fmt.Errorf("data directory, master key and admin token paths are required")
	}
	if config.Listen == "" {
		config.Listen = "127.0.0.1:8080"
	}
	if err := prepareDataDirectory(config.DataDir); err != nil {
		return nil, err
	}
	service := &Service{config: config}
	fail := func(service *Service, err error) (*Service, error) {
		service.Close()
		return nil, err
	}
	runtimeLock, err := acquireRuntimeLock(config.DataDir)
	if err != nil {
		return fail(service, err)
	}
	service.runtimeLock = runtimeLock
	adminToken, err := auth.Load(config.AdminTokenPath)
	if err != nil {
		return fail(service, fmt.Errorf("load admin token: %w", err))
	}
	service.admin = adminToken
	loadOptions := masterkey.RuntimeLoadOptions()
	if config.Development {
		loadOptions = masterkey.LoadOptions{ExpectedUID: -1, ExpectedGID: -1}
	}
	master, err := masterkey.Load(config.MasterKeyPath, loadOptions)
	if err != nil {
		return fail(service, fmt.Errorf("load master key: %w", err))
	}
	defer wipeMaster(&master)
	backupDir := filepath.Join(config.DataDir, "migration-backups")
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		return fail(service, fmt.Errorf("create migration backup directory: %w", err))
	}
	sqliteStore, err := storagesqlite.Open(ctx, filepath.Join(config.DataDir, "proxyloom.db"), storagesqlite.OpenOptions{
		Migrate: storagesqlite.MigrateOptions{
			Now: time.Now,
			BeforeUpgrade: func(ctx context.Context, database *sql.DB, current, target int) error {
				path := filepath.Join(backupDir, fmt.Sprintf("schema-v%d-to-v%d-%s.db", current, target, uuid.New().String()))
				_, err := storagesqlite.CreateVerifiedBackup(ctx, database, path)
				return err
			},
		},
	})
	if err != nil {
		return fail(service, err)
	}
	service.sqlite = sqliteStore
	ring, err := storagesqlite.LoadKeys(ctx, sqliteStore.DB(), master)
	if errors.Is(err, storagesqlite.ErrCryptoNotInitialized) {
		ring, err = storagesqlite.BootstrapKeys(ctx, sqliteStore.DB(), master, storagesqlite.KeyBootstrapOptions{
			Now: time.Now().UTC(), Random: rand.Reader, NewID: newID,
		})
	}
	if err != nil {
		return fail(service, fmt.Errorf("initialize encrypted storage: %w", err))
	}
	service.keys = ring
	adminSessions, err := auth.NewStore(sqliteStore.DB(), ring, auth.StoreOptions{
		Now: time.Now, Random: rand.Reader, NewID: newID,
	})
	if err != nil {
		return fail(service, err)
	}
	service.sessions = adminSessions
	blobs, err := blobstore.New(sqliteStore.DB(), ring, blobstore.Options{
		Root: filepath.Join(config.DataDir, "blobs"), Random: rand.Reader,
		Now: time.Now, NewID: newID,
	})
	if err != nil {
		return fail(service, err)
	}
	sources, err := sourcestore.New(sqliteStore.DB(), sourcestore.Options{Now: time.Now, NewID: newID})
	if err != nil {
		return fail(service, err)
	}
	if recovered, err := sources.RecoverRunningAttempts(ctx); err != nil {
		return fail(service, err)
	} else if recovered > 0 {
		log.Printf("recovered %d interrupted refresh attempts", recovered)
	}
	jobs, err := jobstore.New(sqliteStore.DB(), jobstore.Options{Now: time.Now, NewID: newID})
	if err != nil {
		return fail(service, err)
	}
	artifacts, err := artifactstore.New(sqliteStore.DB(), ring, blobs, artifactstore.Options{
		Now: time.Now, NewID: newID, Random: rand.Reader,
	})
	if err != nil {
		return fail(service, err)
	}
	healthRecords, err := healthstore.New(sqliteStore.DB(), healthstore.Options{Now: time.Now, NewID: newID})
	if err != nil {
		return fail(service, err)
	}
	service.healthStore = healthRecords
	executor12Path := config.SingBoxPath
	if executor12Path == "" {
		executor12Path = singboxexecutor.DefaultPath
	}
	validator12, validator12Err := singboxexecutor.Open(ctx, singboxexecutor.Options{
		Path: executor12Path, ExpectedVersion: singboxexecutor.ExpectedVersion,
	})
	if validator12Err != nil && !config.Development {
		return fail(service, fmt.Errorf("initialize sing-box 1.12.25 validator: %w", validator12Err))
	}
	executor13Path := config.SingBox13Path
	if executor13Path == "" {
		executor13Path = singboxexecutor.DefaultPath13
	}
	validator13, validator13Err := singboxexecutor.Open(ctx, singboxexecutor.Options{
		Path: executor13Path, ExpectedVersion: singboxexecutor.ExpectedVersion13,
	})
	if validator13Err != nil && !config.Development {
		return fail(service, fmt.Errorf("initialize sing-box 1.13.14 validator: %w", validator13Err))
	}
	targetValidators := make(map[string]aggregate.Validator, 3)
	if validator12 != nil {
		targetValidators[outputstore.TargetSingBox11225] = validator12
		targetValidators[outputstore.TargetMomo121] = validator12
	}
	if validator13 != nil {
		targetValidators[outputstore.TargetSingBox11314] = validator13
	}
	var healthScheduler interface {
		SynchronizeSnapshot(context.Context, string, string) error
	}
	healthExecutor := validator12
	if healthExecutor == nil {
		healthExecutor = validator13
	}
	if healthExecutor != nil {
		healthScheduler = healthRecords
		if err := healthRecords.SynchronizeCurrentSnapshots(ctx); err != nil {
			return fail(service, fmt.Errorf("synchronize current node health capabilities: %w", err))
		}
	}
	outputs, err := outputstore.New(sqliteStore.DB(), ring, blobs, outputstore.Options{
		Now: time.Now, NewID: newID, Random: rand.Reader,
	})
	if err != nil {
		return fail(service, err)
	}
	outputJobs, err := outputjobstore.New(sqliteStore.DB(), outputjobstore.Options{Now: time.Now, NewID: newID})
	if err != nil {
		return fail(service, err)
	}
	aggregator, err := aggregate.New(outputs, aggregate.Options{
		Now: time.Now, Validators: targetValidators, Jobs: outputJobs,
		FetchRemote: config.RemoteTemplateFetcher,
	})
	if err != nil {
		return fail(service, err)
	}
	service.outputs = outputs
	service.outputJobs = outputJobs
	service.aggregate = aggregator
	manager, err := app.NewManager(ring, blobs, sources, jobs, artifacts, app.ManagerOptions{
		Now: time.Now, NewID: newID,
		HealthScheduler: healthScheduler, HealthReader: healthRecords, HealthCatalog: healthRecords,
	})
	if err != nil {
		return fail(service, err)
	}
	if healthExecutor != nil {
		healthWorker, err := app.NewHealthWorker(healthRecords, blobs, healthExecutor, app.HealthWorkerOptions{
			Owner: "health-worker-" + newID(), Concurrency: 4, ECHExecutor: validator13, Log: log.Printf,
			OnFilterBoundary: func(ctx context.Context, sourceID string) error {
				sourceErr := manager.EnqueueHealthRebuild(ctx, sourceID)
				outputErr := aggregator.EnqueueForSource(ctx, sourceID, "health_boundary")
				if sourceErr != nil {
					if outputErr != nil {
						return fmt.Errorf("source rebuild: %v; managed outputs: %w", sourceErr, outputErr)
					}
					return sourceErr
				}
				return outputErr
			},
		})
		if err != nil {
			return fail(service, err)
		}
		service.healthWorker = healthWorker
	}
	worker, err := app.NewWorker(manager, jobs, app.WorkerOptions{
		Owner: "worker-" + newID(), Log: log.Printf,
		OnRefreshSuccess: func(ctx context.Context, sourceID string) error {
			return aggregator.EnqueueForSource(ctx, sourceID, "source_refresh")
		},
	})
	if err != nil {
		return fail(service, err)
	}
	outputWorker, err := aggregate.NewWorker(aggregator, outputJobs, aggregate.WorkerOptions{
		Owner: "output-worker-" + newID(), Log: log.Printf,
	})
	if err != nil {
		return fail(service, err)
	}
	api, err := httpapi.New(manager, aggregator, jobs, artifacts, adminToken, adminSessions, httpapi.Options{
		Log: log.Printf, Now: time.Now, NewID: newID,
		PublicOrigin: config.PublicOrigin, CookieSecure: config.SecureCookie,
	})
	if err != nil {
		return fail(service, err)
	}
	service.worker = worker
	service.outputWorker = outputWorker
	service.jobs = jobs
	service.api = api
	service.httpServer = &http.Server{
		Addr: config.Listen, Handler: api.Handler(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 60 * time.Second,
		WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second,
	}
	return service, nil
}

func (s *Service) Serve(ctx context.Context) error {
	if s == nil || s.httpServer == nil || s.worker == nil || s.outputWorker == nil {
		return fmt.Errorf("service is not initialized")
	}
	listener, err := net.Listen("tcp", s.config.Listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.config.Listen, err)
	}
	log.Printf("ProxyLoom listening on http://%s", listener.Addr().String())
	runContext, cancel := context.WithCancel(ctx)
	defer cancel()
	workerDone := make(chan error, 1)
	go func() { workerDone <- s.worker.Run(runContext) }()
	outputWorkerDone := make(chan error, 1)
	go func() { outputWorkerDone <- s.outputWorker.Run(runContext) }()
	var healthDone chan error
	if s.healthWorker != nil {
		healthDone = make(chan error, 1)
		go func() { healthDone <- s.healthWorker.Run(runContext) }()
	}
	serverDone := make(chan error, 1)
	go func() { serverDone <- s.httpServer.Serve(listener) }()
	select {
	case <-ctx.Done():
		cancel()
		shutdownContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := s.httpServer.Shutdown(shutdownContext); err != nil {
			return fmt.Errorf("shutdown HTTP server: %w", err)
		}
		<-workerDone
		<-outputWorkerDone
		if healthDone != nil {
			<-healthDone
		}
		return nil
	case err := <-serverDone:
		cancel()
		<-workerDone
		<-outputWorkerDone
		if healthDone != nil {
			<-healthDone
		}
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case err := <-workerDone:
		cancel()
		_ = s.httpServer.Close()
		<-outputWorkerDone
		if healthDone != nil {
			<-healthDone
		}
		if err != nil {
			return fmt.Errorf("worker stopped: %w", err)
		}
		return nil
	case err := <-outputWorkerDone:
		cancel()
		_ = s.httpServer.Close()
		<-workerDone
		if healthDone != nil {
			<-healthDone
		}
		if err != nil {
			return fmt.Errorf("managed output worker stopped: %w", err)
		}
		return nil
	case err := <-healthDone:
		cancel()
		_ = s.httpServer.Close()
		<-workerDone
		<-outputWorkerDone
		if err != nil {
			return fmt.Errorf("health worker stopped: %w", err)
		}
		return nil
	}
}

func (s *Service) Close() {
	if s == nil {
		return
	}
	if s.admin != nil {
		s.admin.Close()
		s.admin = nil
	}
	if s.keys != nil {
		s.keys.Close()
		s.keys = nil
	}
	if s.sqlite != nil {
		_ = s.sqlite.Close()
		s.sqlite = nil
	}
	if s.runtimeLock != nil {
		releaseRuntimeLock(s.runtimeLock)
		s.runtimeLock = nil
	}
}

func CreateAdministratorSetupToken(ctx context.Context, config Config) (string, time.Time, error) {
	service, err := Open(ctx, config)
	if err != nil {
		return "", time.Time{}, err
	}
	defer service.Close()
	return service.sessions.CreateSetupToken(ctx, auth.DefaultSetupTTL)
}

func RecoverAdministrator(ctx context.Context, config Config, username, password string) error {
	service, err := Open(ctx, config)
	if err != nil {
		return err
	}
	defer service.Close()
	return service.sessions.ResetPassword(ctx, username, password, "local-recovery-"+newID())
}

func RotateMasterKey(ctx context.Context, config Config) (string, error) {
	loadOptions := masterkey.RuntimeLoadOptions()
	generateOptions := masterkey.RuntimeGenerateOptions()
	if config.Development {
		loadOptions = masterkey.LoadOptions{ExpectedUID: -1, ExpectedGID: -1}
		generateOptions = masterkey.GenerateOptions{Random: rand.Reader}
	}
	current, err := masterkey.Load(config.MasterKeyPath, loadOptions)
	if err != nil {
		return "", fmt.Errorf("load current master key for rotation: %w", err)
	}
	defer wipeMaster(&current)
	nextPath := config.MasterKeyPath + ".next"
	previousPath := config.MasterKeyPath + ".previous"
	for _, path := range []string{nextPath, previousPath} {
		if _, err := os.Lstat(path); err == nil {
			return "", fmt.Errorf("master key rotation path already exists: %s", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("inspect master key rotation path: %w", err)
		}
	}
	next, err := masterkey.Generate(nextPath, generateOptions)
	if err != nil {
		return "", fmt.Errorf("generate next master key: %w", err)
	}
	defer wipeMaster(&next)
	removeNext := true
	defer func() {
		if removeNext {
			_ = os.Remove(nextPath)
		}
	}()
	runtime, err := openMaintenance(ctx, config, current)
	if err != nil {
		return "", err
	}
	if err := storagesqlite.PrepareMasterKeyRotation(ctx, runtime.sqlite.DB(), current, next, storagesqlite.MasterKeyRotationOptions{
		Now: time.Now().UTC(), Random: rand.Reader,
	}); err != nil {
		runtime.close()
		return "", err
	}
	if err := runtime.sessions.InsertAudit(ctx, auth.AuditEvent{
		ActorType: "system", Action: "master_key.rotation_prepared",
		ResourceType: "master_key_slot", ResourceID: next.ID,
		Result: "success", CorrelationID: "local-key-rotation-" + newID(),
	}); err != nil {
		runtime.close()
		return "", fmt.Errorf("audit prepared master key rotation: %w", err)
	}
	runtime.close()
	if err := os.Rename(config.MasterKeyPath, previousPath); err != nil {
		return "", fmt.Errorf("preserve previous master key: %w", err)
	}
	if err := os.Rename(nextPath, config.MasterKeyPath); err != nil {
		_ = os.Rename(previousPath, config.MasterKeyPath)
		return "", fmt.Errorf("activate next master key file: %w", err)
	}
	removeNext = false
	if err := syncDirectory(filepath.Dir(config.MasterKeyPath)); err != nil {
		return "", err
	}
	return next.ID, nil
}

func FinalizeMasterKeyRotation(ctx context.Context, config Config) error {
	previousPath := config.MasterKeyPath + ".previous"
	loadOptions := masterkey.RuntimeLoadOptions()
	if config.Development {
		loadOptions = masterkey.LoadOptions{ExpectedUID: -1, ExpectedGID: -1}
	}
	previous, err := masterkey.Load(previousPath, loadOptions)
	if err != nil {
		return fmt.Errorf("load previous master key: %w", err)
	}
	defer wipeMaster(&previous)
	current, err := masterkey.Load(config.MasterKeyPath, loadOptions)
	if err != nil {
		return fmt.Errorf("load active master key: %w", err)
	}
	defer wipeMaster(&current)
	runtime, err := openMaintenance(ctx, config, current)
	if err != nil {
		return err
	}
	defer runtime.close()
	var state string
	if err := runtime.sqlite.DB().QueryRowContext(ctx, `SELECT state FROM master_key_slots WHERE id = ?`, previous.ID).Scan(&state); err != nil {
		return fmt.Errorf("read previous master key slot: %w", err)
	}
	if state != "retired" {
		return fmt.Errorf("previous master key slot is not retired")
	}
	correlationID := "local-key-finalize-" + newID()
	if err := runtime.sessions.InsertAudit(ctx, auth.AuditEvent{
		ActorType: "system", Action: "master_key.rotation_finalize_started",
		ResourceType: "master_key_slot", ResourceID: previous.ID,
		Result: "success", CorrelationID: correlationID,
	}); err != nil {
		return fmt.Errorf("audit master key finalization start: %w", err)
	}
	if err := os.Remove(previousPath); err != nil {
		return fmt.Errorf("remove confirmed previous master key: %w", err)
	}
	if err := syncDirectory(filepath.Dir(config.MasterKeyPath)); err != nil {
		return err
	}
	return runtime.sessions.InsertAudit(ctx, auth.AuditEvent{
		ActorType: "system", Action: "master_key.rotation_finalized",
		ResourceType: "master_key_slot", ResourceID: previous.ID,
		Result: "success", CorrelationID: correlationID,
	})
}

type RestoreInfo struct {
	SourceInstanceID string
	SchemaVersion    int
	RollbackPath     string
}

type DataKeyRotationInfo struct {
	ActiveKeyID string
	BlobCount   int
}

func RotateBlobDataKey(ctx context.Context, config Config) (DataKeyRotationInfo, error) {
	loadOptions := masterkey.RuntimeLoadOptions()
	if config.Development {
		loadOptions = masterkey.LoadOptions{ExpectedUID: -1, ExpectedGID: -1}
	}
	master, err := masterkey.Load(config.MasterKeyPath, loadOptions)
	if err != nil {
		return DataKeyRotationInfo{}, fmt.Errorf("load master key for data key rotation: %w", err)
	}
	defer wipeMaster(&master)
	if err := prepareDataDirectory(config.DataDir); err != nil {
		return DataKeyRotationInfo{}, err
	}
	runtimeLock, err := acquireRuntimeLock(config.DataDir)
	if err != nil {
		return DataKeyRotationInfo{}, fmt.Errorf("data key rotation requires the ProxyLoom service to be stopped: %w", err)
	}
	defer releaseRuntimeLock(runtimeLock)
	runtime, err := openMaintenance(ctx, config, master)
	if err != nil {
		return DataKeyRotationInfo{}, err
	}
	rotation, err := storagesqlite.PrepareDataKeyRotation(ctx, runtime.sqlite.DB(), master, keyring.PurposeBlob, storagesqlite.DataKeyRotationOptions{
		Now: time.Now().UTC(), Random: rand.Reader, NewID: newID,
	})
	runtime.close()
	if err != nil {
		return DataKeyRotationInfo{}, err
	}
	defer func() {
		for index := range rotation.Active.Material {
			rotation.Active.Material[index] = 0
		}
	}()
	runtime, err = openMaintenance(ctx, config, master)
	if err != nil {
		return DataKeyRotationInfo{}, err
	}
	defer runtime.close()
	blobs, err := blobstore.New(runtime.sqlite.DB(), runtime.keys, blobstore.Options{
		Root: filepath.Join(config.DataDir, "blobs"), Random: rand.Reader,
		Now: time.Now, NewID: newID,
	})
	if err != nil {
		return DataKeyRotationInfo{}, err
	}
	processed := 0
	for {
		count, err := blobs.ReencryptBlobKeyBatch(ctx, rotation.OldIDs, 100)
		if err != nil {
			return DataKeyRotationInfo{}, fmt.Errorf("re-encrypt blobs with rotated data key: %w", err)
		}
		processed += count
		if count == 0 {
			break
		}
	}
	if err := storagesqlite.FinalizeBlobDataKeyRotation(ctx, runtime.sqlite.DB(), rotation.OldIDs, time.Now().UTC()); err != nil {
		return DataKeyRotationInfo{}, err
	}
	if err := runtime.sessions.InsertAudit(ctx, auth.AuditEvent{
		ActorType: "system", Action: "data_key.blob_rotated",
		ResourceType: "data_key", ResourceID: rotation.Active.ID,
		Result: "success", CorrelationID: "local-data-key-rotation-" + newID(),
		Details: map[string]interface{}{"blob_count": processed},
	}); err != nil {
		return DataKeyRotationInfo{}, fmt.Errorf("audit blob data key rotation: %w", err)
	}
	return DataKeyRotationInfo{ActiveKeyID: rotation.Active.ID, BlobCount: processed}, nil
}

func CreateManagedBackup(ctx context.Context, config Config, destination string, passphrase []byte) (managedbackup.Info, error) {
	loadOptions := masterkey.RuntimeLoadOptions()
	if config.Development {
		loadOptions = masterkey.LoadOptions{ExpectedUID: -1, ExpectedGID: -1}
	}
	master, err := masterkey.Load(config.MasterKeyPath, loadOptions)
	if err != nil {
		return managedbackup.Info{}, fmt.Errorf("load master key for backup: %w", err)
	}
	defer wipeMaster(&master)
	runtime, err := openMaintenance(ctx, config, master)
	if err != nil {
		return managedbackup.Info{}, err
	}
	defer runtime.close()
	info, err := managedbackup.Create(ctx, runtime.sqlite.DB(), config.DataDir, master, passphrase, destination, time.Now().UTC())
	if err != nil {
		return managedbackup.Info{}, err
	}
	if err := runtime.sessions.InsertAudit(ctx, auth.AuditEvent{
		ActorType: "system", Action: "managed_backup.created",
		ResourceType: "managed_backup", ResourceID: info.SHA256,
		Result: "success", CorrelationID: "local-backup-" + newID(),
		Details: map[string]interface{}{"schema_version": info.SchemaVersion, "size": info.Size},
	}); err != nil {
		return managedbackup.Info{}, fmt.Errorf("audit managed backup: %w", err)
	}
	return info, nil
}

func RestoreManagedBackup(ctx context.Context, config Config, source string, passphrase []byte) (RestoreInfo, error) {
	loadOptions := masterkey.RuntimeLoadOptions()
	if config.Development {
		loadOptions = masterkey.LoadOptions{ExpectedUID: -1, ExpectedGID: -1}
	}
	targetMaster, err := masterkey.Load(config.MasterKeyPath, loadOptions)
	if err != nil {
		return RestoreInfo{}, fmt.Errorf("load target master key for restore: %w", err)
	}
	defer wipeMaster(&targetMaster)
	if err := prepareDataDirectory(config.DataDir); err != nil {
		return RestoreInfo{}, err
	}
	runtimeLock, err := acquireRuntimeLock(config.DataDir)
	if err != nil {
		return RestoreInfo{}, fmt.Errorf("restore requires the ProxyLoom service to be stopped: %w", err)
	}
	defer releaseRuntimeLock(runtimeLock)
	operationID := newID()
	stagingPath := filepath.Join(config.DataDir, ".restore-staging-"+operationID)
	extracted, err := managedbackup.ExtractAndVerify(ctx, source, stagingPath, passphrase)
	if err != nil {
		return RestoreInfo{}, err
	}
	defer os.RemoveAll(extracted.Root)
	defer wipeMaster(&extracted.Master)
	if err := rewrapRestoredDatabase(ctx, extracted.Database, extracted.Master, targetMaster); err != nil {
		return RestoreInfo{}, err
	}

	current, err := openMaintenance(ctx, config, targetMaster)
	if err != nil {
		return RestoreInfo{}, fmt.Errorf("open current instance before restore: %w", err)
	}
	correlationID := "local-restore-" + operationID
	if err := current.sessions.InsertAudit(ctx, auth.AuditEvent{
		ActorType: "system", Action: "managed_backup.restore_started",
		ResourceType: "managed_backup", ResourceID: extracted.Manifest.InstanceID,
		Result: "success", CorrelationID: correlationID,
	}); err != nil {
		current.close()
		return RestoreInfo{}, fmt.Errorf("audit managed restore start: %w", err)
	}
	rollbackPath := filepath.Join(config.DataDir, "restore-backups", operationID)
	if err := os.MkdirAll(rollbackPath, 0o700); err != nil {
		current.close()
		return RestoreInfo{}, fmt.Errorf("create restore rollback directory: %w", err)
	}
	if _, err := storagesqlite.CreateVerifiedBackup(ctx, current.sqlite.DB(), filepath.Join(rollbackPath, "proxyloom.db")); err != nil {
		current.close()
		_ = os.RemoveAll(rollbackPath)
		return RestoreInfo{}, fmt.Errorf("backup current instance before restore: %w", err)
	}
	if _, err := current.sqlite.DB().ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		current.close()
		return RestoreInfo{}, fmt.Errorf("checkpoint current database before restore: %w", err)
	}
	current.close()
	if err := removeSQLiteSidecars(filepath.Join(config.DataDir, "proxyloom.db")); err != nil {
		return RestoreInfo{}, err
	}
	if err := swapRestoredData(config.DataDir, extracted, rollbackPath); err != nil {
		return RestoreInfo{}, err
	}

	restored, err := openMaintenance(ctx, config, targetMaster)
	if err != nil {
		_ = rollbackRestoredData(config.DataDir, extracted.Root, rollbackPath)
		return RestoreInfo{}, fmt.Errorf("open restored instance: %w", err)
	}
	now := time.Now().UTC().UnixMilli()
	if _, err := restored.sqlite.DB().ExecContext(ctx, `UPDATE administrators SET session_epoch = session_epoch + 1, updated_at = ?`, now); err != nil {
		restored.close()
		_ = rollbackRestoredData(config.DataDir, extracted.Root, rollbackPath)
		return RestoreInfo{}, fmt.Errorf("invalidate restored administrator sessions: %w", err)
	}
	if _, err := restored.sqlite.DB().ExecContext(ctx, `UPDATE sessions SET revoked_at = COALESCE(revoked_at, ?)`, now); err != nil {
		restored.close()
		_ = rollbackRestoredData(config.DataDir, extracted.Root, rollbackPath)
		return RestoreInfo{}, fmt.Errorf("revoke restored sessions: %w", err)
	}
	if err := restored.sessions.InsertAudit(ctx, auth.AuditEvent{
		ActorType: "system", Action: "managed_backup.restored",
		ResourceType: "managed_backup", ResourceID: extracted.Manifest.InstanceID,
		Result: "success", CorrelationID: correlationID,
		Details: map[string]interface{}{"schema_version": extracted.Manifest.SchemaVersion},
	}); err != nil {
		restored.close()
		_ = rollbackRestoredData(config.DataDir, extracted.Root, rollbackPath)
		return RestoreInfo{}, fmt.Errorf("audit managed restore completion: %w", err)
	}
	if _, err := restored.sqlite.DB().ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		restored.close()
		return RestoreInfo{}, fmt.Errorf("checkpoint restored database: %w", err)
	}
	restored.close()
	_ = os.Remove(filepath.Join(rollbackPath, "original.db"))
	if err := syncDirectory(config.DataDir); err != nil {
		return RestoreInfo{}, err
	}
	return RestoreInfo{
		SourceInstanceID: extracted.Manifest.InstanceID,
		SchemaVersion:    extracted.Manifest.SchemaVersion, RollbackPath: rollbackPath,
	}, nil
}

func rewrapRestoredDatabase(ctx context.Context, databasePath string, archived, target masterkey.Key) error {
	store, err := storagesqlite.Open(ctx, databasePath, storagesqlite.OpenOptions{
		Migrate: storagesqlite.MigrateOptions{Now: time.Now},
	})
	if err != nil {
		return fmt.Errorf("open staged restore database: %w", err)
	}
	defer store.Close()
	if archived.ID == target.ID {
		ring, err := storagesqlite.LoadKeys(ctx, store.DB(), target)
		if err != nil {
			return fmt.Errorf("verify same-instance restore master key: %w", err)
		}
		ring.Close()
		return nil
	}
	if err := storagesqlite.PrepareMasterKeyRotation(ctx, store.DB(), archived, target, storagesqlite.MasterKeyRotationOptions{
		Now: time.Now().UTC(), Random: rand.Reader,
	}); err != nil {
		return fmt.Errorf("rewrap restored data keys for target instance: %w", err)
	}
	ring, err := storagesqlite.LoadKeys(ctx, store.DB(), target)
	if err != nil {
		return fmt.Errorf("activate target master key in restored database: %w", err)
	}
	ring.Close()
	if _, err := store.DB().ExecContext(ctx, `DELETE FROM master_key_wrappings WHERE master_key_id = ?`, archived.ID); err != nil {
		return fmt.Errorf("remove archived master key wrappings: %w", err)
	}
	if _, err := store.DB().ExecContext(ctx, `DELETE FROM master_key_slots WHERE id = ? AND state = 'retired'`, archived.ID); err != nil {
		return fmt.Errorf("remove archived master key slot: %w", err)
	}
	return nil
}

func swapRestoredData(dataDir string, extracted managedbackup.Extracted, rollbackPath string) error {
	liveDB := filepath.Join(dataDir, "proxyloom.db")
	liveBlobs := filepath.Join(dataDir, "blobs")
	originalDB := filepath.Join(rollbackPath, "original.db")
	originalBlobs := filepath.Join(rollbackPath, "blobs")
	if err := os.Rename(liveDB, originalDB); err != nil {
		return fmt.Errorf("preserve current database for restore: %w", err)
	}
	if err := os.Rename(liveBlobs, originalBlobs); err != nil {
		_ = os.Rename(originalDB, liveDB)
		return fmt.Errorf("preserve current blobs for restore: %w", err)
	}
	if err := os.Rename(extracted.Database, liveDB); err != nil {
		_ = os.Rename(originalBlobs, liveBlobs)
		_ = os.Rename(originalDB, liveDB)
		return fmt.Errorf("activate restored database: %w", err)
	}
	if err := os.Rename(extracted.BlobRoot, liveBlobs); err != nil {
		_ = os.Rename(liveDB, extracted.Database)
		_ = os.Rename(originalBlobs, liveBlobs)
		_ = os.Rename(originalDB, liveDB)
		return fmt.Errorf("activate restored blobs: %w", err)
	}
	if err := syncDirectory(dataDir); err != nil {
		_ = rollbackRestoredData(dataDir, extracted.Root, rollbackPath)
		return err
	}
	return nil
}

func rollbackRestoredData(dataDir, stagingRoot, rollbackPath string) error {
	liveDB := filepath.Join(dataDir, "proxyloom.db")
	liveBlobs := filepath.Join(dataDir, "blobs")
	_ = removeSQLiteSidecars(liveDB)
	_ = os.MkdirAll(stagingRoot, 0o700)
	_ = os.Rename(liveDB, filepath.Join(stagingRoot, "database.sqlite"))
	_ = os.Rename(liveBlobs, filepath.Join(stagingRoot, "blobs"))
	if err := os.Rename(filepath.Join(rollbackPath, "original.db"), liveDB); err != nil {
		return fmt.Errorf("rollback original database after failed restore: %w", err)
	}
	if err := os.Rename(filepath.Join(rollbackPath, "blobs"), liveBlobs); err != nil {
		return fmt.Errorf("rollback original blobs after failed restore: %w", err)
	}
	return syncDirectory(dataDir)
}

func removeSQLiteSidecars(databasePath string) error {
	for _, suffix := range []string{"-wal", "-shm"} {
		path := databasePath + suffix
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove SQLite restore sidecar: %w", err)
		}
	}
	return nil
}

func openMaintenance(ctx context.Context, config Config, master masterkey.Key) (*maintenanceRuntime, error) {
	if config.DataDir == "" || config.MasterKeyPath == "" {
		return nil, fmt.Errorf("data directory and master key path are required")
	}
	if err := prepareDataDirectory(config.DataDir); err != nil {
		return nil, err
	}
	backupDir := filepath.Join(config.DataDir, "migration-backups")
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		return nil, fmt.Errorf("create migration backup directory: %w", err)
	}
	store, err := storagesqlite.Open(ctx, filepath.Join(config.DataDir, "proxyloom.db"), storagesqlite.OpenOptions{
		Migrate: storagesqlite.MigrateOptions{
			Now: time.Now,
			BeforeUpgrade: func(ctx context.Context, database *sql.DB, current, target int) error {
				path := filepath.Join(backupDir, fmt.Sprintf("schema-v%d-to-v%d-%s.db", current, target, uuid.New().String()))
				_, err := storagesqlite.CreateVerifiedBackup(ctx, database, path)
				return err
			},
		},
	})
	if err != nil {
		return nil, err
	}
	runtime := &maintenanceRuntime{sqlite: store}
	fail := func(err error) (*maintenanceRuntime, error) {
		runtime.close()
		return nil, err
	}
	ring, err := storagesqlite.LoadKeys(ctx, store.DB(), master)
	if err != nil {
		return fail(fmt.Errorf("load encrypted storage for maintenance: %w", err))
	}
	runtime.keys = ring
	sessions, err := auth.NewStore(store.DB(), ring, auth.StoreOptions{
		Now: time.Now, Random: rand.Reader, NewID: newID,
	})
	if err != nil {
		return fail(err)
	}
	runtime.sessions = sessions
	return runtime, nil
}

func (r *maintenanceRuntime) close() {
	if r == nil {
		return
	}
	if r.keys != nil {
		r.keys.Close()
		r.keys = nil
	}
	if r.sqlite != nil {
		_ = r.sqlite.Close()
		r.sqlite = nil
	}
}

func syncDirectory(path string) error {
	directory, err := os.Open(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("open secret directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync secret directory: %w", err)
	}
	return nil
}

func prepareDataDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create data directory: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect data directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("data directory must be a real directory")
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return fmt.Errorf("secure data directory: %w", err)
	}
	return nil
}

func wipeMaster(key *masterkey.Key) {
	if key == nil {
		return
	}
	for index := range key.Material {
		key.Material[index] = 0
	}
}

func newID() string { return uuid.New().String() }
