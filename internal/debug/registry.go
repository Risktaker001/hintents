// Copyright 2026 Erst Users
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"time"

	"github.com/dotandev/hintents/internal/snapshot"
)

// FileExtension is the conventional extension for snapshot registry files.
const FileExtension = ".erstsnap"

// Registry stores all state required to replay a time-travel debug session
// without reconnecting to the Stellar network.
type Registry struct {
	// Version is the Erst release that created this file.
	Version string `json:"version"`
	// CreatedAt is when the session was saved.
	CreatedAt time.Time `json:"created_at"`
	// TxHash is the transaction that was debugged.
	TxHash string `json:"tx_hash"`
	// Network is the Stellar network the transaction was fetched from.
	Network string `json:"network"`
	// EnvelopeXdr is the base64-encoded transaction envelope.
	EnvelopeXdr string `json:"envelope_xdr"`
	// ResultMetaXdr is the base64-encoded transaction result metadata.
	ResultMetaXdr string `json:"result_meta_xdr"`
	// Entries holds one ledger snapshot per simulated timestamp.
	Entries []Entry `json:"entries"`
}

// Entry pairs a simulated timestamp with the ledger snapshot used at that point.
type Entry struct {
	Timestamp int64              `json:"timestamp"`
	Snapshot  *snapshot.Snapshot `json:"snapshot"`
}

// New returns an empty Registry for the given transaction.
func New(version, txHash, network, envelopeXdr, resultMetaXdr string) *Registry {
	return &Registry{
		Version:       version,
		CreatedAt:     time.Now().UTC(),
		TxHash:        txHash,
		Network:       network,
		EnvelopeXdr:   envelopeXdr,
		ResultMetaXdr: resultMetaXdr,
	}
}

// Add appends a ledger snapshot captured at the given simulation timestamp.
func (r *Registry) Add(timestamp int64, snap *snapshot.Snapshot) {
	r.Entries = append(r.Entries, Entry{
		Timestamp: timestamp,
		Snapshot:  snap,
	})
}

// SnapshotAt returns the snapshot whose timestamp is closest to ts.
// Returns nil when the registry is empty.
func (r *Registry) SnapshotAt(ts int64) *snapshot.Snapshot {
	if len(r.Entries) == 0 {
		return nil
	}
	best := &r.Entries[0]
	bestDiff := absDiff(r.Entries[0].Timestamp, ts)
	for i := 1; i < len(r.Entries); i++ {
		if d := absDiff(r.Entries[i].Timestamp, ts); d < bestDiff {
			best = &r.Entries[i]
			bestDiff = d
		}
	}
	return best.Snapshot
}

func absDiff(a, b int64) int64 {
	if d := a - b; d < 0 {
		return -d
	} else {
		return d
	}
}
