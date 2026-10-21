package app

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/HeatonZ/egress-filter/internal/pool"
)

// Status serves a JSON health report.
//
// Operators need to see per-route verdicts, not just a count: a pool that says
// "45 ready" while every route answers a blocked 403 is the exact failure this
// service exists to prevent.
func Status(p *pool.Pool, started time.Time, evicted func() int64) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type routeView struct {
			Lease       string `json:"lease"`
			EgressIP    string `json:"egress_ip"`
			State       string `json:"state"`
			Verdict     string `json:"verdict"`
			ConsecOK    int    `json:"consec_ok"`
			ConsecFail  int    `json:"consec_fail"`
			Detail      string `json:"detail,omitempty"`
			Error       string `json:"error,omitempty"`
			LatencyMS   int64  `json:"latency_ms"`
			LastProbeAt string `json:"last_probe_at,omitempty"`
			LastOKAt    string `json:"last_ok_at,omitempty"`
		}

		snaps := p.Snapshots()
		routes := make([]routeView, 0, len(snaps))
		for _, s := range snaps {
			v := routeView{
				Lease:      s.Lease,
				EgressIP:   s.EgressIP,
				State:      s.State.String(),
				Verdict:    s.LastVerdict.String(),
				ConsecOK:   s.ConsecOK,
				ConsecFail: s.ConsecFail,
				Detail:     s.LastDetail,
				Error:      s.LastError,
				LatencyMS:  s.ProbeLatency.Milliseconds(),
			}
			if !s.LastProbeAt.IsZero() {
				v.LastProbeAt = s.LastProbeAt.UTC().Format(time.RFC3339)
			}
			if !s.LastOKAt.IsZero() {
				v.LastOKAt = s.LastOKAt.UTC().Format(time.RFC3339)
			}
			routes = append(routes, v)
		}

		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", " ")
		enc.Encode(map[string]any{
			"counts":         p.Counts(),
			"uptime_seconds": int64(time.Since(started).Seconds()),
			"evicted_total":  evicted(),
			"routes":         routes,
		})
	}
}
