/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import "testing"

func TestWSPendingDial_EnqueueCopiesAndDropsOldest(t *testing.T) {
	var pd wsPendingDial
	buf := []byte{0}
	total := IdealBatchSize + 3
	for i := range total {
		buf[0] = byte(i)
		pd.enqueue([][]byte{buf}) // the caller reuses buf, so the queue must hold copies
	}
	if len(pd.queue) != IdealBatchSize {
		t.Fatalf("queue length = %d, want %d", len(pd.queue), IdealBatchSize)
	}
	for i, p := range pd.queue {
		if want := byte(i + 3); len(p) != 1 || p[0] != want {
			t.Fatalf("queue[%d] = %v, want [%d] (the 3 oldest dropped, order kept)", i, p, want)
		}
	}
}
