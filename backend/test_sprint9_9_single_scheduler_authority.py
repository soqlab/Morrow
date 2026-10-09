import os
import unittest
from unittest.mock import patch


class TestSprint99SingleSchedulerAuthority(unittest.TestCase):
    def tearDown(self):
        # Don't leak env changes into other tests.
        os.environ.pop("WORKER_ROLE", None)

    def test_scheduler_thread_not_started_when_worker_role_set(self):
        os.environ["WORKER_ROLE"] = "api"

        import app as app_module

        # Thread should not be created when WORKER_ROLE is set
        with patch.object(app_module.threading, "Thread") as mock_thread:
            app_module._start_scheduler()
            mock_thread.assert_not_called()

        # Ensure no thread reference was set
        self.assertTrue(
            getattr(app_module, "_SCHED_THREAD", None) is None
            or not getattr(app_module, "_SCHED_THREAD").is_alive()
        )


if __name__ == "__main__":
    unittest.main()
