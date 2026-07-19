package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/doujialong/proxyloom/internal/auth"
	"github.com/doujialong/proxyloom/internal/crypto/masterkey"
	"github.com/doujialong/proxyloom/internal/service"
)

const (
	defaultMasterKeyPath  = "/run/secrets/proxyloom/master.key"
	defaultAdminTokenPath = "/run/secrets/proxyloom/admin.token"
	defaultDataDir        = "/var/lib/proxyloom"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: proxyloom <init-data|init-key|init-admin-token|show-admin-token|bootstrap-token|recover-admin|backup|restore|rotate-data-key|rotate-master-key|finalize-master-key-rotation|serve|healthcheck> [options]")
		return 2
	}
	switch args[0] {
	case "init-data":
		flags := flag.NewFlagSet("init-data", flag.ContinueOnError)
		flags.SetOutput(stderr)
		path := flags.String("path", defaultDataDir, "runtime data directory")
		development := flags.Bool("development", false, "keep current directory ownership for local development")
		if err := flags.Parse(args[1:]); err != nil {
			return 2
		}
		if flags.NArg() != 0 {
			fmt.Fprintln(stderr, "init-data does not accept positional arguments")
			return 2
		}
		if err := os.MkdirAll(filepath.Clean(*path), 0o700); err != nil {
			fmt.Fprintf(stderr, "init-data: %v\n", err)
			return 1
		}
		if !*development {
			if err := os.Chown(*path, masterkey.RuntimeUID, masterkey.RuntimeGID); err != nil {
				fmt.Fprintf(stderr, "init-data: set ownership: %v\n", err)
				return 1
			}
		}
		if err := os.Chmod(*path, 0o700); err != nil {
			fmt.Fprintf(stderr, "init-data: set permissions: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "initialized data directory at %s\n", *path)
		return 0
	case "init-key":
		flags := flag.NewFlagSet("init-key", flag.ContinueOnError)
		flags.SetOutput(stderr)
		path := flags.String("path", defaultMasterKeyPath, "master key output path")
		development := flags.Bool("development", false, "keep current file ownership for local development")
		if err := flags.Parse(args[1:]); err != nil {
			return 2
		}
		if flags.NArg() != 0 {
			fmt.Fprintln(stderr, "init-key does not accept positional arguments")
			return 2
		}
		generateOptions := masterkey.RuntimeGenerateOptions()
		if *development {
			generateOptions = masterkey.GenerateOptions{}
		}
		key, err := masterkey.Generate(*path, generateOptions)
		if err != nil {
			fmt.Fprintf(stderr, "init-key: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "created master key %s at %s\n", key.ID, *path)
		return 0
	case "init-admin-token":
		flags := flag.NewFlagSet("init-admin-token", flag.ContinueOnError)
		flags.SetOutput(stderr)
		path := flags.String("path", defaultAdminTokenPath, "administrator token output path")
		development := flags.Bool("development", false, "keep current file ownership for local development")
		if err := flags.Parse(args[1:]); err != nil {
			return 2
		}
		if flags.NArg() != 0 {
			fmt.Fprintln(stderr, "init-admin-token does not accept positional arguments")
			return 2
		}
		options := auth.GenerateOptions{
			SetOwnership: true, OwnerUID: masterkey.RuntimeUID, OwnerGID: masterkey.RuntimeGID,
		}
		if *development {
			options.SetOwnership = false
		}
		if err := auth.Generate(*path, options); err != nil {
			fmt.Fprintf(stderr, "init-admin-token: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "created administrator token at %s\n", *path)
		return 0
	case "show-admin-token":
		flags := flag.NewFlagSet("show-admin-token", flag.ContinueOnError)
		flags.SetOutput(stderr)
		path := flags.String("path", defaultAdminTokenPath, "administrator token file")
		if err := flags.Parse(args[1:]); err != nil {
			return 2
		}
		if flags.NArg() != 0 {
			fmt.Fprintln(stderr, "show-admin-token does not accept positional arguments")
			return 2
		}
		token, err := auth.Load(*path)
		if err != nil {
			fmt.Fprintf(stderr, "show-admin-token: %v\n", err)
			return 1
		}
		defer token.Close()
		fmt.Fprintln(stdout, token.BearerValue())
		return 0
	case "bootstrap-token":
		flags := flag.NewFlagSet("bootstrap-token", flag.ContinueOnError)
		flags.SetOutput(stderr)
		dataDir := flags.String("data-dir", defaultDataDir, "encrypted data directory")
		masterKeyPath := flags.String("master-key", defaultMasterKeyPath, "master key file")
		adminTokenPath := flags.String("admin-token", defaultAdminTokenPath, "administrator bearer token file")
		development := flags.Bool("development", false, "allow local secret-file ownership")
		if err := flags.Parse(args[1:]); err != nil {
			return 2
		}
		if flags.NArg() != 0 {
			fmt.Fprintln(stderr, "bootstrap-token does not accept positional arguments")
			return 2
		}
		token, expires, err := service.CreateAdministratorSetupToken(context.Background(), service.Config{
			DataDir: *dataDir, MasterKeyPath: *masterKeyPath,
			AdminTokenPath: *adminTokenPath, Development: *development,
		})
		if err != nil {
			fmt.Fprintf(stderr, "bootstrap-token: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, token)
		fmt.Fprintf(stderr, "administrator setup token expires at %s\n", expires.UTC().Format(time.RFC3339))
		return 0
	case "recover-admin":
		flags := flag.NewFlagSet("recover-admin", flag.ContinueOnError)
		flags.SetOutput(stderr)
		dataDir := flags.String("data-dir", defaultDataDir, "encrypted data directory")
		masterKeyPath := flags.String("master-key", defaultMasterKeyPath, "master key file")
		adminTokenPath := flags.String("admin-token", defaultAdminTokenPath, "administrator bearer token file")
		username := flags.String("username", "", "administrator username")
		development := flags.Bool("development", false, "allow local secret-file ownership")
		if err := flags.Parse(args[1:]); err != nil {
			return 2
		}
		if flags.NArg() != 0 || *username == "" {
			fmt.Fprintln(stderr, "recover-admin requires --username and no positional arguments")
			return 2
		}
		password, err := readConfirmedPassword(stdin, stderr)
		if err != nil {
			fmt.Fprintf(stderr, "recover-admin: %v\n", err)
			return 1
		}
		defer wipeStringBytes(password)
		if err := service.RecoverAdministrator(context.Background(), service.Config{
			DataDir: *dataDir, MasterKeyPath: *masterKeyPath,
			AdminTokenPath: *adminTokenPath, Development: *development,
		}, *username, string(password)); err != nil {
			fmt.Fprintf(stderr, "recover-admin: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, "administrator password reset; all existing sessions revoked")
		return 0
	case "backup":
		flags := flag.NewFlagSet("backup", flag.ContinueOnError)
		flags.SetOutput(stderr)
		dataDir := flags.String("data-dir", defaultDataDir, "encrypted data directory")
		masterKeyPath := flags.String("master-key", defaultMasterKeyPath, "master key file")
		output := flags.String("output", "", "managed backup output file")
		development := flags.Bool("development", false, "allow local secret-file ownership")
		if err := flags.Parse(args[1:]); err != nil {
			return 2
		}
		if flags.NArg() != 0 || *output == "" {
			fmt.Fprintln(stderr, "backup requires --output and no positional arguments")
			return 2
		}
		passphrase, err := readBackupPassphrase(stdin, stderr, true)
		if err != nil {
			fmt.Fprintf(stderr, "backup: %v\n", err)
			return 1
		}
		defer wipeStringBytes(passphrase)
		info, err := service.CreateManagedBackup(context.Background(), service.Config{
			DataDir: *dataDir, MasterKeyPath: *masterKeyPath, Development: *development,
		}, *output, passphrase)
		if err != nil {
			fmt.Fprintf(stderr, "backup: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "created encrypted managed backup at %s (sha256=%s, bytes=%d, schema=%d)\n", info.Path, info.SHA256, info.Size, info.SchemaVersion)
		return 0
	case "restore":
		flags := flag.NewFlagSet("restore", flag.ContinueOnError)
		flags.SetOutput(stderr)
		dataDir := flags.String("data-dir", defaultDataDir, "encrypted data directory")
		masterKeyPath := flags.String("master-key", defaultMasterKeyPath, "master key file")
		input := flags.String("input", "", "managed backup input file")
		confirm := flags.Bool("confirm", false, "confirm replacement of the stopped target instance")
		development := flags.Bool("development", false, "allow local secret-file ownership")
		if err := flags.Parse(args[1:]); err != nil {
			return 2
		}
		if flags.NArg() != 0 || *input == "" || !*confirm {
			fmt.Fprintln(stderr, "restore requires --input, --confirm and no positional arguments; stop ProxyLoom first")
			return 2
		}
		passphrase, err := readBackupPassphrase(stdin, stderr, false)
		if err != nil {
			fmt.Fprintf(stderr, "restore: %v\n", err)
			return 1
		}
		defer wipeStringBytes(passphrase)
		info, err := service.RestoreManagedBackup(context.Background(), service.Config{
			DataDir: *dataDir, MasterKeyPath: *masterKeyPath, Development: *development,
		}, *input, passphrase)
		if err != nil {
			fmt.Fprintf(stderr, "restore: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "restored instance %s using target master key; pre-restore backup retained at %s\n", info.SourceInstanceID, info.RollbackPath)
		return 0
	case "rotate-data-key":
		flags := flag.NewFlagSet("rotate-data-key", flag.ContinueOnError)
		flags.SetOutput(stderr)
		dataDir := flags.String("data-dir", defaultDataDir, "encrypted data directory")
		masterKeyPath := flags.String("master-key", defaultMasterKeyPath, "master key file")
		development := flags.Bool("development", false, "allow local secret-file ownership")
		if err := flags.Parse(args[1:]); err != nil {
			return 2
		}
		if flags.NArg() != 0 {
			fmt.Fprintln(stderr, "rotate-data-key does not accept positional arguments; stop ProxyLoom first")
			return 2
		}
		info, err := service.RotateBlobDataKey(context.Background(), service.Config{
			DataDir: *dataDir, MasterKeyPath: *masterKeyPath, Development: *development,
		})
		if err != nil {
			fmt.Fprintf(stderr, "rotate-data-key: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "rotated blob data key to %s and re-encrypted %d blobs\n", info.ActiveKeyID, info.BlobCount)
		return 0
	case "rotate-master-key", "finalize-master-key-rotation":
		commandName := args[0]
		flags := flag.NewFlagSet(commandName, flag.ContinueOnError)
		flags.SetOutput(stderr)
		dataDir := flags.String("data-dir", defaultDataDir, "encrypted data directory")
		masterKeyPath := flags.String("master-key", defaultMasterKeyPath, "master key file")
		adminTokenPath := flags.String("admin-token", defaultAdminTokenPath, "administrator bearer token file")
		development := flags.Bool("development", false, "allow local secret-file ownership")
		if err := flags.Parse(args[1:]); err != nil {
			return 2
		}
		if flags.NArg() != 0 {
			fmt.Fprintf(stderr, "%s does not accept positional arguments\n", commandName)
			return 2
		}
		config := service.Config{
			DataDir: *dataDir, MasterKeyPath: *masterKeyPath,
			AdminTokenPath: *adminTokenPath, Development: *development,
		}
		if commandName == "rotate-master-key" {
			keyID, err := service.RotateMasterKey(context.Background(), config)
			if err != nil {
				fmt.Fprintf(stderr, "rotate-master-key: %v\n", err)
				return 1
			}
			fmt.Fprintf(stdout, "prepared and switched master key %s; restart service, verify readiness, then finalize\n", keyID)
			return 0
		}
		if err := service.FinalizeMasterKeyRotation(context.Background(), config); err != nil {
			fmt.Fprintf(stderr, "finalize-master-key-rotation: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, "master key rotation finalized and previous key file removed")
		return 0
	case "serve":
		flags := flag.NewFlagSet("serve", flag.ContinueOnError)
		flags.SetOutput(stderr)
		dataDir := flags.String("data-dir", defaultDataDir, "encrypted data directory")
		masterKeyPath := flags.String("master-key", defaultMasterKeyPath, "master key file")
		adminTokenPath := flags.String("admin-token", defaultAdminTokenPath, "administrator token file")
		listen := flags.String("listen", "0.0.0.0:8080", "HTTP listen address")
		publicOrigin := flags.String("public-origin", "", "external HTTP(S) origin used for browser origin checks")
		secureCookie := flags.Bool("secure-cookie", false, "mark administrator session cookies Secure")
		singBox12Path := flags.String("sing-box-1.12-path", "", "sing-box 1.12.25 validator and health executor path")
		singBox13Path := flags.String("sing-box-1.13-path", "", "sing-box 1.13.14 validator path")
		development := flags.Bool("development", false, "allow local secret-file ownership")
		if err := flags.Parse(args[1:]); err != nil {
			return 2
		}
		if flags.NArg() != 0 {
			fmt.Fprintln(stderr, "serve does not accept positional arguments")
			return 2
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		runtime, err := service.Open(ctx, service.Config{
			DataDir: *dataDir, MasterKeyPath: *masterKeyPath,
			AdminTokenPath: *adminTokenPath, Listen: *listen,
			Development: *development, PublicOrigin: *publicOrigin, SecureCookie: *secureCookie,
			SingBoxPath: *singBox12Path, SingBox13Path: *singBox13Path,
		})
		if err != nil {
			fmt.Fprintf(stderr, "serve: %v\n", err)
			return 1
		}
		defer runtime.Close()
		if err := runtime.Serve(ctx); err != nil {
			fmt.Fprintf(stderr, "serve: %v\n", err)
			return 1
		}
		return 0
	case "healthcheck":
		flags := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
		flags.SetOutput(stderr)
		url := flags.String("url", "http://127.0.0.1:8080/readyz", "readiness URL")
		if err := flags.Parse(args[1:]); err != nil {
			return 2
		}
		if flags.NArg() != 0 {
			fmt.Fprintln(stderr, "healthcheck does not accept positional arguments")
			return 2
		}
		client := &http.Client{Timeout: 3 * time.Second}
		response, err := client.Get(*url)
		if err != nil {
			fmt.Fprintf(stderr, "healthcheck: %v\n", err)
			return 1
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			fmt.Fprintf(stderr, "healthcheck: HTTP %d\n", response.StatusCode)
			return 1
		}
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		return 2
	}
}

func readConfirmedPassword(input io.Reader, prompt io.Writer) ([]byte, error) {
	reader := bufio.NewReader(io.LimitReader(input, 4098))
	fmt.Fprintln(prompt, "enter new administrator password, then repeat it on the next line:")
	first, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("read first password: %w", err)
	}
	second, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("read password confirmation: %w", err)
	}
	first = strings.TrimSuffix(strings.TrimSuffix(first, "\n"), "\r")
	second = strings.TrimSuffix(strings.TrimSuffix(second, "\n"), "\r")
	if first != second {
		return nil, fmt.Errorf("password confirmation does not match")
	}
	if len(first) == 0 || len(first) > 1024 {
		return nil, fmt.Errorf("administrator password must be non-empty and contain at most 1024 bytes")
	}
	return []byte(first), nil
}

func readBackupPassphrase(input io.Reader, prompt io.Writer, confirm bool) ([]byte, error) {
	reader := bufio.NewReader(io.LimitReader(input, 4098))
	if confirm {
		fmt.Fprintln(prompt, "enter the backup passphrase, then repeat it on the next line:")
	} else {
		fmt.Fprintln(prompt, "enter the backup passphrase:")
	}
	first, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("read backup passphrase: %w", err)
	}
	first = strings.TrimSuffix(strings.TrimSuffix(first, "\n"), "\r")
	if len(first) < 12 || len(first) > 1024 {
		return nil, fmt.Errorf("backup passphrase must contain 12 to 1024 bytes")
	}
	if confirm {
		second, err := reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("read backup passphrase confirmation: %w", err)
		}
		second = strings.TrimSuffix(strings.TrimSuffix(second, "\n"), "\r")
		if first != second {
			return nil, fmt.Errorf("backup passphrase confirmation does not match")
		}
	}
	return []byte(first), nil
}

func wipeStringBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
