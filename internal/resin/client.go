// Package resin talks to the Resin control plane: it lists leases and evicts
// the ones whose egress is blocked.
//
// Eviction is deliberately narrow. Deleting a lease only drops the sticky
// binding; Resin immediately re-allocates the account on the next request. It
// does not touch the node pool itself, so it is safe to do while traffic flows.
package resin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Lease is one sticky binding from an account name to a node.
type Lease struct {
	PlatformID   string `json:"platform_id"`
	Account      string `json:"account"`
	NodeHash     string `json:"node_hash"`
	NodeTag      string `json:"node_tag"`
	EgressIP     string `json:"egress_ip"`
	Expiry       string `json:"expiry"`
	LastAccessed string `json:"last_accessed"`
}

type leasePage struct {
	Items  []Lease `json:"items"`
	Total  int     `json:"total"`
	Limit  int     `json:"limit"`
	Offset int     `json:"offset"`
}

// Client is a minimal Resin admin API client.
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

// New builds a client. baseURL is the Resin root, e.g. http://resin:2260.
func New(baseURL, token string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Token:   token,
		HTTP: &http.Client{
			Timeout: 20 * time.Second,
		},
	}
}

func (c *Client) do(ctx context.Context, method, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")
	return c.HTTP.Do(req)
}

// Leases returns every lease of a platform, following pagination.
func (c *Client) Leases(ctx context.Context, platformID string) ([]Lease, error) {
	const pageSize = 200
	var out []Lease
	offset := 0
	for {
		path := fmt.Sprintf("/api/v1/platforms/%s/leases?limit=%d&offset=%d",
			url.PathEscape(platformID), pageSize, offset)
		resp, err := c.do(ctx, http.MethodGet, path)
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("list leases: status %d: %s", resp.StatusCode, snippet(body))
		}
		var page leasePage
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("list leases: decode: %w", err)
		}
		out = append(out, page.Items...)
		offset += len(page.Items)
		// Stop on a short page, or when the server's total says we are done.
		// Both conditions are checked because a concurrent delete can move the
		// total while we are paging.
		if len(page.Items) == 0 || offset >= page.Total {
			break
		}
		if len(page.Items) < pageSize {
			break
		}
	}
	return out, nil
}

// DeleteLease drops the sticky binding for account, so the next request binds a
// different node.
func (c *Client) DeleteLease(ctx context.Context, platformID, account string) error {
	path := fmt.Sprintf("/api/v1/platforms/%s/leases/%s",
		url.PathEscape(platformID), url.PathEscape(account))
	resp, err := c.do(ctx, http.MethodDelete, path)
	if err != nil {
		return err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	resp.Body.Close()
	// 404 means someone else already removed it, which is the desired end state
	// as far as the caller is concerned.
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("delete lease %s: status %d: %s", account, resp.StatusCode, snippet(body))
	}
	return nil
}

// Healthy pings the control plane.
func (c *Client) Healthy(ctx context.Context) error {
	resp, err := c.HTTP.Get(c.BaseURL + "/healthz")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz: status %d", resp.StatusCode)
	}
	return nil
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}
