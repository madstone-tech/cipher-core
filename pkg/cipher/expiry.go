package cipher

import "context"

// ExpiringKeys returns every key that carries an expiry date, in the order the
// repository yields them.
//
// It is a pure read: it sends no notifications, dispatches no webhooks and
// writes no audit entries. Those belong to the server, which owns the
// notification sweep and the tier gating that governs it — keeping them out of
// here is what stops WebhookDispatcher and AuditLogger leaking into this
// library's public surface.
func (c *Client) ExpiringKeys(ctx context.Context) ([]*KeyInfo, error) {
	keys, err := c.keyRepo.ListWithExpiry(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*KeyInfo, 0, len(keys))
	for _, k := range keys {
		out = append(out, toKeyInfo(k))
	}
	return out, nil
}
