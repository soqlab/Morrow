"""Keep arbitrary request targets out of the default Uvicorn access log."""
import logging


class AccessLogFilter(logging.Filter):
    def filter(self, record):
        # Uvicorn logs (client, method, full_path, http_version, status). The raw path
        # can itself contain a credential; route templates live in the admin journal.
        if isinstance(record.args, tuple) and len(record.args) == 5:
            args = list(record.args)
            args[2] = "[route omitted; see protected traffic monitor]"
            record.args = tuple(args)
        return True


def install_access_log_filter():
    target = logging.getLogger("uvicorn.access")
    if not any(isinstance(item, AccessLogFilter) for item in target.filters):
        target.addFilter(AccessLogFilter())
