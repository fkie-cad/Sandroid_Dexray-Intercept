import contextlib
import io
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from dexray_intercept import ammm


def application(identifier, pid):
    return SimpleNamespace(identifier=identifier, pid=pid)


class AttachResolutionTests(unittest.TestCase):
    def setUp(self):
        self.device = Mock()

    def test_pid_does_not_enumerate_applications(self):
        self.assertEqual(
            ammm.resolve_attach_target(self.device, "1234"),
            ("1234", 1234),
        )
        self.device.enumerate_applications.assert_not_called()

    def test_exact_identifier_resolves_to_running_pid(self):
        self.device.enumerate_applications.return_value = [
            application("com.test.lifecyclee2e", 42)
        ]
        self.assertEqual(
            ammm.resolve_attach_target(
                self.device, "com.test.lifecyclee2e"
            ),
            ("com.test.lifecyclee2e", 42),
        )

    def test_identifier_matching_is_case_sensitive(self):
        self.device.enumerate_applications.return_value = [
            application("com.test.lifecyclee2e", 42)
        ]
        target = "com.Test.lifecyclee2e"
        self.assertEqual(
            ammm.resolve_attach_target(self.device, target),
            (target, target),
        )

    def test_process_name_is_passed_through(self):
        self.device.enumerate_applications.return_value = []
        self.assertEqual(
            ammm.resolve_attach_target(self.device, "LifecycleE2E"),
            ("LifecycleE2E", "LifecycleE2E"),
        )

    def test_stopped_application_is_rejected(self):
        self.device.enumerate_applications.return_value = [
            application("com.test.lifecyclee2e", 0)
        ]
        with self.assertRaisesRegex(
            ammm.AttachTargetResolutionError, "not running"
        ):
            ammm.resolve_attach_target(
                self.device, "com.test.lifecyclee2e"
            )

    def test_ambiguous_identifier_is_rejected(self):
        self.device.enumerate_applications.return_value = [
            application("com.test.lifecyclee2e", 42),
            application("com.test.lifecyclee2e", 43),
        ]
        with self.assertRaisesRegex(
            ammm.AttachTargetResolutionError, "ambiguous"
        ):
            ammm.resolve_attach_target(
                self.device, "com.test.lifecyclee2e"
            )

    def test_foreground_uses_pid(self):
        self.device.get_frontmost_application.return_value = application(
            "com.test.lifecyclee2e", 42
        )
        self.assertEqual(
            ammm.resolve_attach_target(self.device, None, foreground=True),
            ("com.test.lifecyclee2e", 42),
        )

    def test_missing_foreground_application_is_rejected(self):
        self.device.get_frontmost_application.return_value = None
        with self.assertRaises(ammm.AttachTargetResolutionError):
            ammm.resolve_attach_target(self.device, None, foreground=True)

    def test_foreground_without_running_pid_is_rejected(self):
        self.device.get_frontmost_application.return_value = application(
            "com.test.lifecyclee2e", 0
        )
        with self.assertRaises(ammm.AttachTargetResolutionError):
            ammm.resolve_attach_target(self.device, None, foreground=True)

    def test_enumeration_failure_is_not_silenced(self):
        self.device.enumerate_applications.side_effect = RuntimeError(
            "enumeration failed"
        )
        with self.assertRaisesRegex(RuntimeError, "enumeration failed"):
            ammm.resolve_attach_target(self.device, "some-name")


class ModeValidationTests(unittest.TestCase):
    def test_invalid_foreground_combinations_exit_before_server_setup(self):
        cases = [
            ["-fg", "com.test.lifecyclee2e"],
            ["-fg", "-s"],
            ["-fg", "-s", "com.test.lifecyclee2e"],
        ]

        for args in cases:
            with self.subTest(args=args):
                with patch.object(
                    sys, "argv", ["dexray-intercept"] + args
                ), patch.object(
                    ammm, "setup_frida_server"
                ) as setup, contextlib.redirect_stdout(
                    io.StringIO()
                ), self.assertRaises(SystemExit) as raised:
                    ammm.main()

                self.assertEqual(raised.exception.code, 2)
                setup.assert_not_called()


if __name__ == "__main__":
    unittest.main()