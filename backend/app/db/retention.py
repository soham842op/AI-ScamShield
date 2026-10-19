from datetime import timedelta

# Retention periods. The purge job deletes rows older than these.
ANALYSIS_RECORD_RETENTION = timedelta(days=90)
FEEDBACK_RETENTION = timedelta(days=90)
RATE_LIMIT_RETENTION = timedelta(hours=48)
