from __future__ import annotations

import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest

from live_runtime.calendar_review import (
    CalendarReviewError,
    assemble_prewindow_calendar_review,
    calendar_review_key_name,
    load_calendar_review_artifact,
    load_calendar_source_manifest,
    prepare_calendar_review_evidence,
    sign_calendar_review_approval,
    verify_prewindow_calendar_review,
    write_calendar_review_artifact_exclusive,
)


ROOT = Path(__file__).resolve().parent
UTC = timezone.utc
NOW = datetime(2026, 7, 21, 12, 0, tzinfo=UTC)
KEY = b"calendar-review-key-material-at-least-32-bytes"


def load_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def template_for(candidate_id: str) -> dict[str, object]:
    filename = {
        "phillip-fx": "phillip_fx_calendar_window_01.template.json",
        "phillip-commodity": "phillip_commodity_calendar_window_01.template.json",
    }[candidate_id]
    return load_json(ROOT / "config" / filename)


def candidate_config() -> dict[str, object]:
    return load_json(ROOT / "config/broker_candidates.phase3.json")


def source_claim(
    source_id: str,
    source_role: str,
    filename: str,
    *,
    url: str,
    published_on: str | None,
) -> dict[str, object]:
    return {
        "source_id": source_id,
        "source_role": source_role,
        "url": url,
        "published_on": published_on,
        "observed_at_utc": "2026-07-21T10:00:00Z",
        "source_file": filename,
    }


def manifest_for(candidate_id: str) -> dict[str, object]:
    if candidate_id == "phillip-fx":
        sources = [
            source_claim(
                "fx-service-hours",
                "REGULAR_FX_SESSION_SCHEDULE",
                "fx-hours.html",
                url="https://www.phillip.co.jp/fx/servicelist.php",
                published_on=None,
            ),
            source_claim(
                "dst-2026",
                "DST_TRANSITION_NOTICE",
                "dst.html",
                url="https://www.phillip.co.jp/information/info/10999",
                published_on="2026-03-05",
            ),
        ]
    else:
        sources = [
            source_claim(
                "xau-important-notes",
                "COMMODITY_XAU_SESSION_SCHEDULE",
                "commodity.pdf",
                url="https://www.phillip.co.jp/fx/pdf/C-CFD_important_notes.pdf",
                published_on="2026-06-01",
            )
        ]
    return {
        "schema_version": "prewindow-calendar-source-manifest-v1",
        "candidate_id": candidate_id,
        "future_exception_completeness": False,
        "sources": sources,
    }


def write_sources(root: Path, candidate_id: str) -> None:
    if candidate_id == "phillip-fx":
        (root / "fx-hours.html").write_bytes(b"official FX service hours")
        (root / "dst.html").write_bytes(b"official 2026 DST notice")
    else:
        (root / "commodity.pdf").write_bytes(b"official XAU session document")


def prepare(
    root: Path,
    candidate_id: str = "phillip-fx",
    *,
    manifest: dict[str, object] | None = None,
    template: dict[str, object] | None = None,
) -> dict[str, object]:
    write_sources(root, candidate_id)
    return prepare_calendar_review_evidence(
        candidate_config(),
        template or template_for(candidate_id),
        manifest or manifest_for(candidate_id),
        source_root=root,
        now_provider=lambda: NOW,
    )


def approved_review(
    root: Path,
    candidate_id: str = "phillip-fx",
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    template = template_for(candidate_id)
    evidence = prepare(root, candidate_id, template=template)
    key_id = calendar_review_key_name(candidate_id)
    approval = sign_calendar_review_approval(
        evidence,
        reviewer_id="calendar-reviewer",
        key_id=key_id,
        signing_key=KEY,
        now_provider=lambda: NOW,
    )
    review = assemble_prewindow_calendar_review(
        evidence,
        approval,
        template=template,
        approval_key_provider={key_id: KEY}.get,
        now_provider=lambda: NOW,
    )
    return template, evidence, review


class CalendarReviewTests(unittest.TestCase):
    def test_fx_evidence_is_derived_from_exact_source_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = prepare(Path(directory))
        self.assertEqual("phillip-fx", evidence["candidate_id"])
        self.assertEqual(
            {"REGULAR_FX_SESSION_SCHEDULE", "DST_TRANSITION_NOTICE"},
            {item["source_role"] for item in evidence["official_sources"]},
        )
        self.assertTrue(all(item["captured_content_bytes"] > 0 for item in evidence["official_sources"]))
        self.assertFalse(evidence["special_hours_attested"])
        self.assertFalse(evidence["future_exception_completeness"])
        self.assertFalse(evidence["execution_enabled"])
        self.assertEqual(0.01, evidence["max_lot"])

    def test_commodity_review_is_lane_isolated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = prepare(Path(directory), "phillip-commodity")
        self.assertEqual({"XAUUSD"}, set(evidence["broker_symbols"]))
        self.assertEqual(
            ["COMMODITY_XAU_SESSION_SCHEDULE"],
            [item["source_role"] for item in evidence["official_sources"]],
        )

    def test_missing_required_role_and_cross_lane_manifest_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_sources(root, "phillip-fx")
            missing = manifest_for("phillip-fx")
            missing["sources"] = missing["sources"][:1]
            with self.assertRaisesRegex(CalendarReviewError, "required source roles"):
                prepare_calendar_review_evidence(
                    candidate_config(),
                    template_for("phillip-fx"),
                    missing,
                    source_root=root,
                    now_provider=lambda: NOW,
                )
            cross = manifest_for("phillip-commodity")
            with self.assertRaisesRegex(CalendarReviewError, "lane binding"):
                prepare_calendar_review_evidence(
                    candidate_config(),
                    template_for("phillip-fx"),
                    cross,
                    source_root=root,
                    now_provider=lambda: NOW,
                )

    def test_source_url_and_identity_attacks_fail_closed(self) -> None:
        mutations = {
            "http": lambda item: item.update(url="http://www.phillip.co.jp/fx/servicelist.php"),
            "wrong_host": lambda item: item.update(url="https://example.com/fx"),
            "port": lambda item: item.update(url="https://www.phillip.co.jp:443/fx"),
            "fragment": lambda item: item.update(url="https://www.phillip.co.jp/fx#hours"),
            "duplicate_id": None,
            "future_publication": lambda item: item.update(published_on="2026-07-22"),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                manifest = manifest_for("phillip-fx")
                if label == "duplicate_id":
                    manifest["sources"][1]["source_id"] = manifest["sources"][0]["source_id"]
                else:
                    mutate(manifest["sources"][0])
                write_sources(root, "phillip-fx")
                with self.assertRaises(CalendarReviewError):
                    prepare_calendar_review_evidence(
                        candidate_config(),
                        template_for("phillip-fx"),
                        manifest,
                        source_root=root,
                        now_provider=lambda: NOW,
                    )

    def test_duplicate_source_role_fails_even_when_required_roles_exist(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = manifest_for("phillip-fx")
            duplicate = copy.deepcopy(manifest["sources"][0])
            duplicate["source_id"] = "duplicate-regular-hours"
            manifest["sources"].append(duplicate)
            write_sources(root, "phillip-fx")
            with self.assertRaisesRegex(CalendarReviewError, "role is duplicated"):
                prepare_calendar_review_evidence(
                    candidate_config(),
                    template_for("phillip-fx"),
                    manifest,
                    source_root=root,
                    now_provider=lambda: NOW,
                )

    def test_source_file_escape_symlink_and_empty_file_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_sources(root, "phillip-fx")
            for source_file in ("../outside", "", str(root / "fx-hours.html")):
                manifest = manifest_for("phillip-fx")
                manifest["sources"][0]["source_file"] = source_file
                with self.subTest(source_file=source_file), self.assertRaises(CalendarReviewError):
                    prepare_calendar_review_evidence(
                        candidate_config(), template_for("phillip-fx"), manifest,
                        source_root=root, now_provider=lambda: NOW,
                    )
            (root / "fx-hours.html").write_bytes(b"")
            with self.assertRaises(CalendarReviewError):
                prepare_calendar_review_evidence(
                    candidate_config(), template_for("phillip-fx"), manifest_for("phillip-fx"),
                    source_root=root, now_provider=lambda: NOW,
                )
            target = root / "real.html"
            target.write_bytes(b"source")
            link = root / "fx-hours.html"
            link.unlink()
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable")
            with self.assertRaises(CalendarReviewError):
                prepare_calendar_review_evidence(
                    candidate_config(), template_for("phillip-fx"), manifest_for("phillip-fx"),
                    source_root=root, now_provider=lambda: NOW,
                )

    def test_prewindow_workflow_rejects_false_completeness_claims(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            template = template_for("phillip-fx")
            template["special_hours_review"]["attested"] = True
            with self.assertRaisesRegex(CalendarReviewError, "must remain false"):
                prepare(root, template=template)
            manifest = manifest_for("phillip-fx")
            manifest["future_exception_completeness"] = True
            with self.assertRaisesRegex(CalendarReviewError, "completeness"):
                prepare(root, manifest=manifest)

    def test_approval_and_assembled_review_verify_without_secret_export(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            template, evidence, review = approved_review(Path(directory))
        key_id = calendar_review_key_name("phillip-fx")
        verify_prewindow_calendar_review(
            review,
            template=template,
            approval_key_provider={key_id: KEY}.get,
            now_provider=lambda: NOW,
        )
        serialized = json.dumps(review)
        self.assertNotIn(KEY.decode(), serialized)
        self.assertEqual(evidence["evidence_bundle_sha256"], review["evidence_bundle_sha256"])
        self.assertFalse(review["future_exception_completeness"])
        self.assertTrue(review["amendment_chain_required"])
        self.assertTrue(review["post_window_completeness_required"])

    def test_tampered_wrong_or_missing_approval_key_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            template, _, review = approved_review(Path(directory))
        key_id = calendar_review_key_name("phillip-fx")
        cases = [
            ({"calendar_review_approval": {**review["calendar_review_approval"], "reviewer_role": "LEGAL_REVIEW"}}, {key_id: KEY}.get),
            ({}, {}.get),
            ({}, {key_id: b"short"}.get),
            ({}, {key_id: b"wrong-calendar-review-key-material-32bytes"}.get),
        ]
        for changes, provider in cases:
            with self.subTest(changes=changes, provider=provider):
                candidate = copy.deepcopy(review)
                candidate.update(changes)
                if changes:
                    body = {k: v for k, v in candidate.items() if k != "review_artifact_sha256"}
                    from live_runtime.contracts import canonical_sha256
                    candidate["review_artifact_sha256"] = canonical_sha256(body)
                with self.assertRaises(CalendarReviewError):
                    verify_prewindow_calendar_review(
                        candidate, template=template,
                        approval_key_provider=provider, now_provider=lambda: NOW,
                    )

    def test_schedule_drift_and_cross_lane_review_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            template, _, review = approved_review(Path(directory))
        key_id = calendar_review_key_name("phillip-fx")
        drifted = copy.deepcopy(template)
        drifted["weekly_m15_sessions"]["EURUSD"][0]["open_local"] = "07:15"
        with self.assertRaisesRegex(CalendarReviewError, "schedule claim"):
            verify_prewindow_calendar_review(
                review, template=drifted,
                approval_key_provider={key_id: KEY}.get, now_provider=lambda: NOW,
            )
        with self.assertRaisesRegex(CalendarReviewError, "lane binding"):
            verify_prewindow_calendar_review(
                review, template=template_for("phillip-commodity"),
                approval_key_provider={key_id: KEY}.get, now_provider=lambda: NOW,
            )

    def test_review_time_must_be_fresh_and_before_observation_start(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = prepare(root)
            key_id = calendar_review_key_name("phillip-fx")
            with self.assertRaises(CalendarReviewError):
                sign_calendar_review_approval(
                    evidence, reviewer_id="reviewer", key_id=key_id,
                    signing_key=KEY,
                    now_provider=lambda: datetime(2026, 7, 26, 16, 0, tzinfo=UTC),
                )

    def test_manifest_reader_and_exclusive_writer_are_strict(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "manifest.json"
            path.write_text(json.dumps(manifest_for("phillip-fx")), encoding="utf-8")
            self.assertEqual("phillip-fx", load_calendar_source_manifest(path)["candidate_id"])
            path.write_text('{"schema_version":"x","schema_version":"y"}', encoding="utf-8")
            with self.assertRaises(CalendarReviewError):
                load_calendar_source_manifest(path)
            destination = root / "review.json"
            payload = {"schema_version": "test"}
            write_calendar_review_artifact_exclusive(destination, payload)
            with self.assertRaises((FileExistsError, CalendarReviewError)):
                write_calendar_review_artifact_exclusive(destination, payload)
            loaded = load_calendar_review_artifact(
                destination, expected_fields={"schema_version"}
            )
            self.assertEqual(payload, loaded)

    def test_key_name_is_lane_scoped_and_role_specific(self) -> None:
        self.assertEqual(
            "phillip-fx-prewindow-calendar-review-v1",
            calendar_review_key_name("phillip-fx"),
        )
        self.assertNotEqual(
            calendar_review_key_name("phillip-fx"),
            calendar_review_key_name("phillip-commodity"),
        )


if __name__ == "__main__":
    unittest.main()
