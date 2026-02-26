// Copyright 2025 Erst Users
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"
	"math"
	"strings"

	"github.com/dotandev/hintents/internal/session"
)

const (
	sessionLookupListLimit = 200
)

func resourceNotFoundError(suggestion string) error {
	if suggestion != "" {
		return fmt.Errorf("Resource not found. Did you mean %s?", suggestion)
	}
	return fmt.Errorf("Resource not found.")
}

func suggestSessionID(ctx context.Context, store *session.Store, input string) (string, error) {
	sessions, err := store.List(ctx, sessionLookupListLimit)
	if err != nil {
		return "", err
	}

	candidates := make([]string, 0, len(sessions))
	for _, s := range sessions {
		if s == nil || s.ID == "" {
			continue
		}
		candidates = append(candidates, s.ID)
	}

	return closestStringMatch(input, candidates), nil
}

func closestStringMatch(input string, candidates []string) string {
	in := strings.ToLower(strings.TrimSpace(input))
	if in == "" || len(candidates) == 0 {
		return ""
	}

	bestCandidate := ""
	bestScore := math.Inf(-1)
	bestDistance := int(^uint(0) >> 1)

	for _, candidate := range candidates {
		c := strings.TrimSpace(candidate)
		if c == "" {
			continue
		}

		cn := strings.ToLower(c)
		if cn == in {
			return candidate
		}

		distance := levenshteinDistance(in, cn)
		maxLen := len(in)
		if len(cn) > maxLen {
			maxLen = len(cn)
		}
		if maxLen == 0 {
			continue
		}

		score := 1.0 - float64(distance)/float64(maxLen)

		// Prefix and containment bonuses make CLI IDs more forgiving.
		if strings.HasPrefix(cn, in) || strings.HasPrefix(in, cn) {
			score += 0.25
		}
		if strings.Contains(cn, in) || strings.Contains(in, cn) {
			score += 0.10
		}

		if score > bestScore || (score == bestScore && distance < bestDistance) {
			bestScore = score
			bestDistance = distance
			bestCandidate = candidate
		}
	}

	// Keep suggestions conservative to avoid noisy wrong hints.
	if bestCandidate == "" {
		return ""
	}
	if bestScore >= 0.55 || bestDistance <= 2 {
		return bestCandidate
	}
	return ""
}

func levenshteinDistance(a, b string) int {
	if a == b {
		return 0
	}
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}

	prev := make([]int, len(b)+1)
	curr := make([]int, len(b)+1)

	for j := 0; j <= len(b); j++ {
		prev[j] = j
	}

	for i := 1; i <= len(a); i++ {
		curr[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 0
			if a[i-1] != b[j-1] {
				cost = 1
			}

			del := prev[j] + 1
			ins := curr[j-1] + 1
			sub := prev[j-1] + cost

			curr[j] = del
			if ins < curr[j] {
				curr[j] = ins
			}
			if sub < curr[j] {
				curr[j] = sub
			}
		}
		prev, curr = curr, prev
	}

	return prev[len(b)]
}
