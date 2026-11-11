package manager

import (
	"testing"
)

type dummyClient struct{}

func (d *dummyClient) Start() error                       { return nil }
func (d *dummyClient) Close() error                       { return nil }
func (d *dummyClient) RuntimeDetail(string) (any, error) { return nil, nil }

func TestStartIdempotentWhenAlreadyStarted(t *testing.T) {
	mux.Lock()
	client = &dummyClient{}
	mux.Unlock()

	defer func() {
		mux.Lock()
		client = nil
		mux.Unlock()
	}()

	if !GetIsStarted() {
		t.Fatal("expected GetIsStarted() to be true")
	}

	err := Start()
	if err != nil {
		t.Fatalf("expected Start() to return nil when already started, got: %v", err)
	}

	if !GetIsStarted() {
		t.Fatal("expected GetIsStarted() to remain true")
	}
}
