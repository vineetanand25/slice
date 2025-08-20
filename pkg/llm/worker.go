package llm

import (
	"context"
	"log/slog"
	"sync"

	"github.com/noperator/slice/pkg/logging"
)

// WorkProcessor defines the interface for processing work items
type WorkProcessor[TIn, TOut any] interface {
	Process(ctx context.Context, input TIn) (TOut, error)
}

// ProcessFunc is a function type that implements WorkProcessor
type ProcessFunc[TIn, TOut any] func(ctx context.Context, input TIn) (TOut, error)

// Process implements WorkProcessor for ProcessFunc
func (f ProcessFunc[TIn, TOut]) Process(ctx context.Context, input TIn) (TOut, error) {
	return f(ctx, input)
}

// WorkItem represents a single item to process with its index for ordering
type WorkItem[T any] struct {
	Index int
	Data  T
}

// WorkResult represents the result of processing with its original index
type WorkResult[T any] struct {
	Index int
	Data  T
	Error error
}

// WorkerPool manages concurrent processing of work items
type WorkerPool[TIn, TOut any] struct {
	concurrency int
	logger      *slog.Logger
}

// NewWorkerPool creates a new worker pool with the specified concurrency
func NewWorkerPool[TIn, TOut any](concurrency int) *WorkerPool[TIn, TOut] {
	if concurrency <= 0 {
		concurrency = 1
	}
	return &WorkerPool[TIn, TOut]{
		concurrency: concurrency,
		logger:      logging.NewLoggerFromEnv(),
	}
}

// ProcessItems processes items concurrently while preserving order
func (wp *WorkerPool[TIn, TOut]) ProcessItems(
	ctx context.Context,
	items []TIn,
	processor WorkProcessor[TIn, TOut],
	taskName string,
) ([]TOut, error) {
	numItems := len(items)
	if numItems == 0 {
		return []TOut{}, nil
	}

	wp.logger.Info("processing items",
		"component", "worker_pool",
		"operation", "process_items",
		"task", taskName,
		"items", numItems,
		"concurrency", wp.concurrency)

	workChan := make(chan WorkItem[TIn], numItems)
	resultChan := make(chan WorkResult[TOut], numItems)

	var wg sync.WaitGroup
	for i := 0; i < wp.concurrency; i++ {
		wg.Add(1)
		go wp.worker(ctx, processor, workChan, resultChan, &wg, i)
	}

	for i, item := range items {
		workChan <- WorkItem[TIn]{Index: i, Data: item}
	}
	close(workChan)

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	results := make([]TOut, numItems)
	completed := 0
	var firstErr error

	for result := range resultChan {
		if result.Index >= 0 && result.Index < numItems {
			results[result.Index] = result.Data
			if result.Error != nil && firstErr == nil {
				firstErr = result.Error
			}
		}
		completed++
		wp.logger.Debug("progress update",
			"component", "worker_pool",
			"task", taskName,
			"completed", completed,
			"total", numItems)
	}

	return results, firstErr
}

// worker processes work items from the work channel
func (wp *WorkerPool[TIn, TOut]) worker(
	ctx context.Context,
	processor WorkProcessor[TIn, TOut],
	workChan <-chan WorkItem[TIn],
	resultChan chan<- WorkResult[TOut],
	wg *sync.WaitGroup,
	workerID int,
) {
	defer wg.Done()

	for work := range workChan {
		select {
		case <-ctx.Done():
			return
		default:
		}

		result, err := processor.Process(ctx, work.Data)
		
		if err != nil {
			wp.logger.Warn("worker processing error",
				"component", "worker_pool",
				"worker_id", workerID,
				"work_index", work.Index,
				"error", err)
		}
		
		resultChan <- WorkResult[TOut]{
			Index: work.Index,
			Data:  result,
			Error: err,
		}
	}
}

