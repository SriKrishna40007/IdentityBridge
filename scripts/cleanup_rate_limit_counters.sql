-- Remove expired authentication rate-limit windows.
-- Run daily; only historical counters older than 24 hours are deleted.

DELETE FROM rate_limit_counters
WHERE window_start < (CURRENT_TIMESTAMP - INTERVAL '24 hours');
