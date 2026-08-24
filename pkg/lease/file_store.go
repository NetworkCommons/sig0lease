package lease

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// FileLeaseStore is a LeaseStorage backend that keeps the full lease tree in
// memory (via the embedded *InMemoryLeaseStore, which supplies every
// LeaseStorage data method) and additionally persists it as human-readable
// JSON using the existing SaveSnapshot/LoadSnapshot mechanism: once on
// construction (load-on-start), on a periodic ticker, and once more,
// synchronously, on Stop() (flush-on-shutdown).
type FileLeaseStore struct {
	*InMemoryLeaseStore
	path         string
	saveInterval time.Duration
	onSaveError  func(error)

	saveMu   sync.Mutex // serializes SaveSnapshot calls (ticker vs Stop's final save)
	ticker   *time.Ticker
	stopCh   chan struct{}
	doneCh   chan struct{} // closed once the background goroutine has exited
	stopOnce sync.Once
}

var _ LeaseStorage = (*FileLeaseStore)(nil)

// NewFileLeaseStore creates a file-backed lease store.
//
//   - path's parent directory is created (including any missing ancestors)
//     if it does not already exist. Failure to create it is a hard
//     construction-time error, not a silent fallback to some other location.
//   - If a file already exists at path, it is loaded immediately. A present
//     but corrupt/unparseable file is a hard error -- data loss must be
//     loud, never silently treated as "start empty".
//   - If no file exists yet, the store starts empty.
//   - Either way, NewFileLeaseStore performs one synchronous save to path
//     before returning, so an unwritable path/directory is also a hard
//     construction-time error rather than a silent background failure
//     discovered only much later on the first periodic tick.
//   - onSaveError is invoked (from the background goroutine, and once more
//     from Stop()) if a later periodic or final save fails. It may be nil,
//     in which case such failures are dropped.
func NewFileLeaseStore(path string, saveInterval time.Duration, onSaveError func(error)) (*FileLeaseStore, error) {
	if path == "" {
		return nil, fmt.Errorf("file lease store: path is empty")
	}
	if saveInterval <= 0 {
		return nil, fmt.Errorf("file lease store: save_interval must be positive, got %s", saveInterval)
	}
	if onSaveError == nil {
		onSaveError = func(error) {}
	}

	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("file lease store: cannot create directory %s: %w", dir, err)
		}
	}

	inner := NewInMemoryManager()
	if _, statErr := os.Stat(path); statErr == nil {
		if err := inner.LoadSnapshot(path); err != nil {
			return nil, fmt.Errorf("file lease store: existing snapshot %s is corrupt or unreadable: %w", path, err)
		}
	} else if !os.IsNotExist(statErr) {
		return nil, fmt.Errorf("file lease store: cannot stat %s: %w", path, statErr)
	}

	// Write probe: catches an unwritable path/directory now, not on the
	// first background tick.
	if err := inner.SaveSnapshot(path); err != nil {
		return nil, fmt.Errorf("file lease store: cannot write snapshot to %s: %w", path, err)
	}

	fs := &FileLeaseStore{
		InMemoryLeaseStore: inner,
		path:               path,
		saveInterval:       saveInterval,
		onSaveError:        onSaveError,
		ticker:             time.NewTicker(saveInterval),
		stopCh:             make(chan struct{}),
		doneCh:             make(chan struct{}),
	}
	go fs.runPeriodicSave()
	return fs, nil
}

func (fs *FileLeaseStore) runPeriodicSave() {
	defer close(fs.doneCh)
	for {
		select {
		case <-fs.ticker.C:
			if err := fs.save(); err != nil {
				fs.onSaveError(fmt.Errorf("periodic snapshot save to %s failed: %w", fs.path, err))
			}
		case <-fs.stopCh:
			return
		}
	}
}

func (fs *FileLeaseStore) save() error {
	fs.saveMu.Lock()
	defer fs.saveMu.Unlock()
	return fs.SaveSnapshot(fs.path) // promoted from *InMemoryLeaseStore
}

// Stop stops the periodic-save goroutine and performs one final synchronous
// save so state as of Stop() is not lost. Safe to call more than once (only
// the first call does anything). This overrides the embedded
// InMemoryLeaseStore's no-op Stop() by ordinary Go method-shadowing.
func (fs *FileLeaseStore) Stop() {
	fs.stopOnce.Do(func() {
		fs.ticker.Stop()
		close(fs.stopCh)
		<-fs.doneCh // wait for the goroutine to fully exit so its own
		// in-flight save (if any) can't race the final save below
		if err := fs.save(); err != nil {
			fs.onSaveError(fmt.Errorf("final snapshot save to %s failed: %w", fs.path, err))
		}
	})
}
