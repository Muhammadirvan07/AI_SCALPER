from __future__ import annotations

from contextlib import redirect_stdout
import io
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

import assemble_signed_broker_calendar_template as cli


class AssembleSignedBrokerCalendarTemplateTests(unittest.TestCase):
    def test_materializes_verified_after_image_without_activation(self) -> None:
        profile = SimpleNamespace(candidate_id="phillip-commodity")
        base = {
            "schema_version": "broker-calendar-plan-template-v2",
            "candidate_id": "phillip-commodity",
            "calendar_version": "phillip-commodity-window-02-v1",
        }
        review = {
            "candidate_id": "phillip-commodity",
            "review_artifact_sha256": "a" * 64,
        }
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("template.json", "review.json"):
                (root / name).write_text("{}", encoding="utf-8")
            destination = root / "signed.json"
            with (
                mock.patch.object(
                    cli,
                    "load_broker_evidence_profile",
                    return_value=profile,
                ),
                mock.patch.object(cli, "read_json_object", return_value=base),
                mock.patch.object(
                    cli,
                    "load_prewindow_calendar_review",
                    return_value=review,
                ),
                mock.patch.object(cli, "verify_broker_calendar_template") as verify,
                mock.patch.object(cli, "verify_prewindow_calendar_review") as review_verify,
                mock.patch.object(cli, "WindowsEvidenceKeyStore") as store,
                mock.patch.object(
                    cli,
                    "write_json_exclusive",
                    return_value=destination,
                ) as writer,
                redirect_stdout(output),
            ):
                result = cli.main(
                    [
                        "--candidate",
                        "phillip-commodity",
                        "--template",
                        str(root / "template.json"),
                        "--calendar-review",
                        str(root / "review.json"),
                        "--output",
                        str(destination),
                    ]
                )
        self.assertEqual(0, result)
        self.assertEqual(2, verify.call_count)
        signed = writer.call_args.args[1]
        self.assertEqual("broker-calendar-plan-template-v3", signed["schema_version"])
        self.assertEqual(review, signed["prewindow_calendar_review"])
        self.assertIs(
            review_verify.call_args.kwargs["approval_key_provider"],
            store.return_value.load,
        )
        self.assertIn("Configuration mutated: false", output.getvalue())
        self.assertIn("Registration enabled: false", output.getvalue())
        self.assertIn("Order capability: DISABLED", output.getvalue())

    def test_rejects_candidate_mismatch_before_write(self) -> None:
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with (
                mock.patch.object(
                    cli,
                    "load_broker_evidence_profile",
                    return_value=SimpleNamespace(candidate_id="phillip-commodity"),
                ),
                mock.patch.object(
                    cli,
                    "read_json_object",
                    return_value={
                        "schema_version": "broker-calendar-plan-template-v2",
                        "candidate_id": "phillip-fx",
                    },
                ),
                mock.patch.object(
                    cli,
                    "load_prewindow_calendar_review",
                    return_value={"candidate_id": "phillip-commodity"},
                ),
                mock.patch.object(cli, "write_json_exclusive") as writer,
                redirect_stdout(output),
            ):
                result = cli.main(
                    [
                        "--candidate",
                        "phillip-commodity",
                        "--template",
                        str(root / "template.json"),
                        "--calendar-review",
                        str(root / "review.json"),
                        "--output",
                        str(root / "signed.json"),
                    ]
                )
        self.assertEqual(2, result)
        writer.assert_not_called()
        self.assertIn("candidate binding is invalid", output.getvalue())


if __name__ == "__main__":
    unittest.main()
