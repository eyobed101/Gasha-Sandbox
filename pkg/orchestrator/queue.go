package orchestrator

import (
	"errors"
	"sync"

	"github.com/lemas-sandbox/lemas/pkg/storage"
)

type JobQueue struct {
	mu   sync.Mutex
	jobs []*storage.Job
	cond *sync.Cond
}

func NewJobQueue() *JobQueue {
	q := &JobQueue{}
	q.cond = sync.NewCond(&q.mu)
	return q
}

// Push appends a job to the analysis queue.
func (q *JobQueue) Push(job *storage.Job) {
	q.mu.Lock()
	defer q.mu.Unlock()
	
	q.jobs = append(q.jobs, job)
	q.cond.Signal()
}

// Pop blocks until a job is available and returns it.
func (q *JobQueue) Pop() (*storage.Job, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	for len(q.jobs) == 0 {
		q.cond.Wait()
	}

	if len(q.jobs) == 0 {
		return nil, errors.New("queue is empty")
	}

	job := q.jobs[0]
	q.jobs = q.jobs[1:]
	return job, nil
}

// Length returns the current number of pending items.
func (q *JobQueue) Length() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.jobs)
}
