from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest

from live_runtime.account_identity import payload_hmac_sha256
from live_runtime.calendar_review import calendar_review_key_name
from live_runtime.contracts import canonical_sha256
from live_runtime.evidence_bootstrap import DISCOVERY_RECEIPT_DOMAIN
from live_runtime.phillip_commodity_window_02_rollover import (
    CURRENT_CONTRACT_ID,
    CURRENT_DISCOVERY_KEY_NAME,
    CURRENT_PROFILE_STATUS,
    CURRENT_SNAPSHOT_ID,
    CURRENT_TEMPLATE_PATH,
    PROPOSED_CONTRACT_ID,
    PROPOSED_PROFILE_STATUS,
    PROPOSED_SNAPSHOT_ID,
    PROPOSED_TEMPLATE_PATH,
    RolloverReviewError,
    build_phillip_commodity_window_02_rollover_review,
    verify_phillip_commodity_window_02_rollover_review,
    write_phillip_commodity_window_02_rollover_review_exclusive,
)
from live_runtime.registration_review import (
    REGULATORY_SOURCE_MANIFEST_SCHEMA_VERSION,
    assemble_regulatory_observation,
    prepare_regulatory_evidence,
    regulatory_review_key_name,
    sign_regulatory_approval,
)
from test_live_runtime_calendar_review import (
    KEY as CALENDAR_KEY,
    approved_review,
)
from test_live_runtime_evidence_bootstrap import (
    TEST_KEY as DISCOVERY_KEY,
    discovery_receipt,
)


ROOT = Path(__file__).resolve().parent
UTC = timezone.utc
NOW = datetime(2026, 8, 4, 12, 0, tzinfo=UTC)
COMPLIANCE_KEY = b"window-02-compliance-key-material-distinct-v1"
LEGAL_KEY = b"window-02-legal-key-material-distinct-v1-000"


def _json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _resign_discovery(receipt: dict[str, object]) -> dict[str, object]:
    body = deepcopy(receipt)
    body.pop("payload_sha256", None)
    body.pop("receipt_hmac_sha256", None)
    body["account"]["leverage"] = 20
    signed = {**body, "payload_sha256": canonical_sha256(body)}
    return {
        **signed,
        "receipt_hmac_sha256": payload_hmac_sha256(
            signed,
            DISCOVERY_KEY,
            domain=DISCOVERY_RECEIPT_DOMAIN,
        ),
    }


class PhillipCommodityWindow02RolloverReviewTests(unittest.TestCase):
    def setUp(self) -> None:
        self.candidates = _json(ROOT / "config/broker_candidates.phase3.json")
        self.profiles = _json(ROOT / "config/broker_evidence_profiles.v1.json")
        self.release_allowlist = _json(
            ROOT / "config/windows_release_allowlist.v1.json"
        )
        historical_profile = next(
            item
            for item in self.profiles["profiles"]
            if item["candidate_id"] == "phillip-commodity"
        )
        historical_profile.update(
            {
                "snapshot_id": CURRENT_SNAPSHOT_ID,
                "contract_id": CURRENT_CONTRACT_ID,
                "template_path": CURRENT_TEMPLATE_PATH,
                "registration_enabled": True,
                "status": CURRENT_PROFILE_STATUS,
            }
        )
        self.release_allowlist["files"].remove(PROPOSED_TEMPLATE_PATH)
        self.template = _json(
            ROOT
            / "config/phillip_commodity_calendar_window_02.review-template.json"
        )
        self.keys = {
            regulatory_review_key_name(
                "phillip-commodity", "COMPLIANCE_REVIEW"
            ): COMPLIANCE_KEY,
            regulatory_review_key_name(
                "phillip-commodity", "LEGAL_REVIEW"
            ): LEGAL_KEY,
            calendar_review_key_name("phillip-commodity"): CALENDAR_KEY,
        }

    def _regulatory_observation(self, root: Path) -> dict[str, object]:
        (root / "fsa-registry.pdf").write_bytes(
            b"official-fsa-registry-window-02-kanto-kinsho-127"
        )
        manifest = {
            "schema_version": REGULATORY_SOURCE_MANIFEST_SCHEMA_VERSION,
            "candidate_id": "phillip-commodity",
            "operating_jurisdiction": "JP",
            "sources": [
                {
                    "authority": "Japan Financial Services Agency",
                    "url": (
                        "https://www.fsa.go.jp/menkyo/menkyoj/"
                        "kinyushohin.pdf"
                    ),
                    "entity": "Phillip Securities Japan, Ltd.",
                    "result": "ENTITY_REGISTERED_FOR_JAPAN_RESIDENTS",
                    "registry_record_id": "KANTO-KINSHO-127",
                    "observed_at_utc": "2026-08-04T10:00:00Z",
                    "source_file": "fsa-registry.pdf",
                }
            ],
        }
        evidence = prepare_regulatory_evidence(
            self.candidates,
            self.template,
            manifest,
            source_root=root,
            now_provider=lambda: NOW - timedelta(minutes=20),
        )
        approvals = []
        reviewers = {
            "COMPLIANCE_REVIEW": "muhammad-irvan",
            "LEGAL_REVIEW": "maulana-putra",
        }
        for index, role in enumerate(("COMPLIANCE_REVIEW", "LEGAL_REVIEW")):
            key_name = regulatory_review_key_name("phillip-commodity", role)
            approvals.append(
                sign_regulatory_approval(
                    evidence,
                    approver_id=reviewers[role],
                    approver_role=role,
                    key_id=key_name,
                    signing_key=self.keys[key_name],
                    now_provider=lambda index=index: NOW
                    - timedelta(minutes=10 - index),
                )
            )
        return assemble_regulatory_observation(
            evidence,
            approvals,
            self.candidates,
            approval_key_provider=self.keys.get,
            now_provider=lambda: NOW,
            template=self.template,
        )

    def _calendar_review(self, root: Path) -> dict[str, object]:
        _, _, review = approved_review(
            root,
            "phillip-commodity",
            template=self.template,
        )
        return review

    def _discovery(self) -> dict[str, object]:
        receipt = discovery_receipt(
            candidate_id="phillip-commodity",
            company="Phillip Securities Japan, Ltd.",
            server="PhillipSecuritiesJP-PROD",
            required_symbols=("XAUUSD",),
            broker_symbols={"XAUUSD": "XAUUSD.ps01"},
        )
        return _resign_discovery(receipt)

    def _arguments(self) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as regulatory_directory:
            regulatory = self._regulatory_observation(
                Path(regulatory_directory)
            )
        with tempfile.TemporaryDirectory() as calendar_directory:
            calendar = self._calendar_review(Path(calendar_directory))
        return {
            "candidate_id": "phillip-commodity",
            "candidate_config": self.candidates,
            "profile_config": self.profiles,
            "release_allowlist": self.release_allowlist,
            "review_template": self.template,
            "signed_template_destination_exists": False,
            "discovery": self._discovery(),
            "regulatory_observation": regulatory,
            "calendar_review": calendar,
            "discovery_signing_key": DISCOVERY_KEY,
            "regulatory_key_provider": self.keys.get,
            "calendar_key_provider": self.keys.get,
            "git_identity": {
                "clean": True,
                "commit_sha": "a" * 40,
                "tree_sha": "b" * 40,
            },
            "now_provider": lambda: NOW,
        }

    def _pack(self) -> dict[str, object]:
        return build_phillip_commodity_window_02_rollover_review(
            **self._arguments()
        )

    def test_valid_pack_is_non_mutating_and_exactly_bounded(self) -> None:
        original_candidates = deepcopy(self.candidates)
        original_profiles = deepcopy(self.profiles)
        original_template = deepcopy(self.template)

        pack = self._pack()
        verify_phillip_commodity_window_02_rollover_review(pack)

        self.assertEqual(original_candidates, self.candidates)
        self.assertEqual(original_profiles, self.profiles)
        self.assertEqual(original_template, self.template)
        self.assertFalse(pack["configuration_mutated"])
        self.assertTrue(pack["registration_enabled"])
        self.assertTrue(pack["manual_rollover_required"])
        self.assertEqual("DISABLED", pack["apply_capability"])
        self.assertEqual("NOT_PERFORMED", pack["contract_registration"])
        self.assertEqual("NOT_PERFORMED", pack["scheduler_mutation"])
        self.assertEqual("NOT_PERFORMED", pack["broker_mutation"])
        self.assertEqual("DISABLED", pack["order_capability"])
        self.assertEqual(4, len(pack["proposed_files"]))

    def test_profile_preserves_key_and_registration_while_rolling_window(self) -> None:
        pack = self._pack()
        profile_file = next(
            item
            for item in pack["proposed_files"]
            if item["path"] == "config/broker_evidence_profiles.v1.json"
        )
        base = next(
            item
            for item in profile_file["base_content"]["profiles"]
            if item["candidate_id"] == "phillip-commodity"
        )
        proposed = next(
            item
            for item in profile_file["proposed_content"]["profiles"]
            if item["candidate_id"] == "phillip-commodity"
        )
        self.assertEqual(CURRENT_DISCOVERY_KEY_NAME, base["key_name"])
        self.assertEqual(base["key_name"], proposed["key_name"])
        self.assertTrue(base["registration_enabled"])
        self.assertTrue(proposed["registration_enabled"])
        self.assertEqual(CURRENT_CONTRACT_ID, base["contract_id"])
        self.assertEqual(PROPOSED_CONTRACT_ID, proposed["contract_id"])
        self.assertEqual(PROPOSED_SNAPSHOT_ID, proposed["snapshot_id"])
        self.assertEqual(PROPOSED_PROFILE_STATUS, proposed["status"])

    def test_signed_template_is_create_only_and_review_template_is_immutable(self) -> None:
        pack = self._pack()
        template_file = next(
            item
            for item in pack["proposed_files"]
            if item["path"]
            == "config/phillip_commodity_calendar_window_02.template.json"
        )
        self.assertEqual("CREATE", template_file["operation"])
        self.assertIsNone(template_file["before_sha256"])
        self.assertIsNone(template_file["base_content"])
        signed = template_file["proposed_content"]
        normalized = deepcopy(signed)
        review = normalized.pop("prewindow_calendar_review")
        normalized["schema_version"] = "broker-calendar-plan-template-v2"
        self.assertEqual(self.template, normalized)
        self.assertEqual(
            pack["calendar_review_artifact_sha256"],
            review["review_artifact_sha256"],
        )
        self.assertEqual(
            canonical_sha256(self.template), pack["review_template_sha256"]
        )

        allowlist_file = next(
            item
            for item in pack["proposed_files"]
            if item["path"] == "config/windows_release_allowlist.v1.json"
        )
        self.assertEqual("REPLACE", allowlist_file["operation"])
        base_files = allowlist_file["base_content"]["files"]
        proposed_files = allowlist_file["proposed_content"]["files"]
        self.assertNotIn(
            "config/phillip_commodity_calendar_window_02.template.json",
            base_files,
        )
        self.assertEqual(
            ["config/phillip_commodity_calendar_window_02.template.json"],
            [path for path in proposed_files if path not in base_files],
        )

    def test_wrong_keys_and_shared_credentials_fail_closed(self) -> None:
        arguments = self._arguments()
        cases = (
            {"discovery_signing_key": b"x" * 40},
            {"regulatory_key_provider": lambda _: b"y" * 40},
            {"calendar_key_provider": lambda _: b"z" * 40},
            {"calendar_key_provider": lambda _: DISCOVERY_KEY},
        )
        for change in cases:
            with self.subTest(change=tuple(change)), self.assertRaises(
                RolloverReviewError
            ):
                build_phillip_commodity_window_02_rollover_review(
                    **{**arguments, **change}
                )

    def test_baseline_or_destination_drift_is_rejected(self) -> None:
        arguments = self._arguments()
        mutations: list[dict[str, object]] = []

        wrong_profile = deepcopy(self.profiles)
        selected = next(
            item
            for item in wrong_profile["profiles"]
            if item["candidate_id"] == "phillip-commodity"
        )
        selected["contract_id"] = "phillip-commodity-window-01-diagnostic-v4"
        mutations.append({"profile_config": wrong_profile})

        disabled = deepcopy(self.profiles)
        next(
            item
            for item in disabled["profiles"]
            if item["candidate_id"] == "phillip-commodity"
        )["registration_enabled"] = False
        mutations.append({"profile_config": disabled})
        mutations.append({"signed_template_destination_exists": True})
        mutations.append(
            {
                "git_identity": {
                    "clean": False,
                    "commit_sha": "a" * 40,
                    "tree_sha": "b" * 40,
                }
            }
        )
        unsafe_template = deepcopy(self.template)
        unsafe_template["max_lot"] = 0.02
        mutations.append({"review_template": unsafe_template})

        for mutation in mutations:
            with self.subTest(mutation=tuple(mutation)), self.assertRaises(
                RolloverReviewError
            ):
                build_phillip_commodity_window_02_rollover_review(
                    **{**arguments, **mutation}
                )

    def test_static_verifier_rejects_operation_content_and_safety_tampering(self) -> None:
        pack = self._pack()
        mutations = []

        unsafe = deepcopy(pack)
        unsafe["order_capability"] = "ENABLED"
        mutations.append(unsafe)

        wrong_operation = deepcopy(pack)
        wrong_operation["proposed_files"][0]["operation"] = "CREATE"
        mutations.append(wrong_operation)

        profile_drift = deepcopy(pack)
        profile_file = next(
            item
            for item in profile_drift["proposed_files"]
            if item["path"] == "config/broker_evidence_profiles.v1.json"
        )
        profile_file["proposed_content"]["max_lot"] = 0.02
        profile_file["after_sha256"] = canonical_sha256(
            profile_file["proposed_content"]
        )
        mutations.append(profile_drift)

        schedule_drift = deepcopy(pack)
        template_file = next(
            item
            for item in schedule_drift["proposed_files"]
            if item["operation"] == "CREATE"
        )
        template_file["proposed_content"]["blind_until_utc"] = (
            "2026-10-13T15:00:00Z"
        )
        template_file["after_sha256"] = canonical_sha256(
            template_file["proposed_content"]
        )
        mutations.append(schedule_drift)

        allowlist_drift = deepcopy(pack)
        allowlist_file = next(
            item
            for item in allowlist_drift["proposed_files"]
            if item["path"] == "config/windows_release_allowlist.v1.json"
        )
        allowlist_file["proposed_content"]["files"].append("unexpected.py")
        allowlist_file["after_sha256"] = canonical_sha256(
            allowlist_file["proposed_content"]
        )
        mutations.append(allowlist_drift)

        duplicate_reviewers = deepcopy(pack)
        candidate_file = next(
            item
            for item in duplicate_reviewers["proposed_files"]
            if item["path"] == "config/broker_candidates.phase3.json"
        )
        proposed_candidate = next(
            item
            for item in candidate_file["proposed_content"]["candidates"]
            if item["candidate_id"] == "phillip-commodity"
        )
        approvals = proposed_candidate["regulatory_observation"][
            "regulatory_approvals"
        ]
        approvals[1]["approver_id"] = approvals[0]["approver_id"].upper()
        candidate_file["after_sha256"] = canonical_sha256(
            candidate_file["proposed_content"]
        )
        duplicate_reviewers["proposed_regulatory_observation_sha256"] = (
            canonical_sha256(proposed_candidate["regulatory_observation"])
        )
        mutations.append(duplicate_reviewers)

        unsafe_current = deepcopy(pack)
        candidate_file = next(
            item
            for item in unsafe_current["proposed_files"]
            if item["path"] == "config/broker_candidates.phase3.json"
        )
        base_candidate = next(
            item
            for item in candidate_file["base_content"]["candidates"]
            if item["candidate_id"] == "phillip-commodity"
        )
        current = base_candidate["regulatory_observation"]
        current["live_allowed"] = True
        evidence_body = {
            key: value
            for key, value in current.items()
            if key not in {"evidence_bundle_sha256", "regulatory_approvals"}
        }
        current["evidence_bundle_sha256"] = canonical_sha256(evidence_body)
        for approval in current["regulatory_approvals"]:
            approval["evidence_bundle_sha256"] = current[
                "evidence_bundle_sha256"
            ]
        candidate_file["before_sha256"] = canonical_sha256(
            candidate_file["base_content"]
        )
        unsafe_current["current_regulatory_observation_sha256"] = (
            canonical_sha256(current)
        )
        mutations.append(unsafe_current)

        for mutation in mutations:
            mutation["proposal_sha256"] = canonical_sha256(
                {
                    key: value
                    for key, value in mutation.items()
                    if key != "proposal_sha256"
                }
            )
            with self.subTest(), self.assertRaises(RolloverReviewError):
                verify_phillip_commodity_window_02_rollover_review(mutation)

    def test_writer_is_create_exclusive(self) -> None:
        pack = self._pack()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "window-02-rollover-review.json"
            written = write_phillip_commodity_window_02_rollover_review_exclusive(
                output,
                pack,
            )
            self.assertEqual(output, written)
            with self.assertRaises(FileExistsError):
                write_phillip_commodity_window_02_rollover_review_exclusive(
                    output,
                    pack,
                )


if __name__ == "__main__":
    unittest.main()
