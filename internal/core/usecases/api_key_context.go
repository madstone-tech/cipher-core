package usecases

// APIKeyCtx holds API key info for request context.
type APIKeyCtx struct {
	UserID string
	Scopes []string
}

// HasScope returns true if the context has the given scope or "admin".
func (c *APIKeyCtx) HasScope(scope string) bool {
	for _, s := range c.Scopes {
		if s == scope || s == "admin" {
			return true
		}
	}
	return false
}
