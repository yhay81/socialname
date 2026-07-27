CREATE INDEX searches_history_page
ON searches (tenant_id, created_at DESC, id DESC);
