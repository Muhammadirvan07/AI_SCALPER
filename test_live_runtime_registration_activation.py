from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest

from live_runtime.account_identity import payload_hmac_sha256
from live_runtime.contracts import canonical_sha256
from live_runtime.evidence_bootstrap import DISCOVERY_RECEIPT_DOMAIN
from live_runtime.registration_activation import (
    PROPOSED_REGISTRATION_STATUS,
    RegistrationActivationError,
    build_registration_activation_review_pack,
    verify_registration_activation_review_pack,
    write_registration_activation_review_pack_exclusive,
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
    calendar_review_key_name,
)
from test_live_runtime_evidence_bootstrap import (
    TEST_KEY as DISCOVERY_KEY,
    discovery_receipt,
)


ROOT = Path(__file__).resolve().parent
UTC = timezone.utc
NOW = datetime(2026, 7, 21, 12, 10, tzinfo=UTC)
COMPLIANCE_KEY = b"phillip-fx-compliance-review-key-material-v1"
LEGAL_KEY = b"phillip-fx-legal-review-key-material-v1-32bytes"


def _json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _resign_discovery(
    receipt: dict[str, object],
    *,
    leverage: int,
) -> dict[str, object]:
    body = deepcopy(receipt)
    body.pop("payload_sha256", None)
    body.pop("receipt_hmac_sha256", None)
    body["account"]["leverage"] = leverage
    signed = {**body, "payload_sha256": canonical_sha256(body)}
    return {
        **signed,
        "receipt_hmac_sha256": payload_hmac_sha256(
            signed,
            DISCOVERY_KEY,
            domain=DISCOVERY_RECEIPT_DOMAIN,
        ),
    }


class RegistrationActivationReviewTests(unittest.TestCase):
    def setUp(self) -> None:
        self.candidates = _json(ROOT / "config/broker_candidates.phase3.json")
        self.profiles = _json(ROOT / "config/broker_evidence_profiles.v1.json")
        self.templates = {
            "phillip-fx": _json(
                ROOT / "config/phillip_fx_calendar_window_01.template.json"
            ),
            "phillip-commodity": _json(
                ROOT
                / "config/phillip_commodity_calendar_window_01.template.json"
            ),
        }
        self.template = self.templates["phillip-fx"]
        self.keys = {}
        for candidate_id in self.templates:
            self.keys.update(
                {
                    regulatory_review_key_name(
                        candidate_id, "COMPLIANCE_REVIEW"
                    ): COMPLIANCE_KEY,
                    regulatory_review_key_name(
                        candidate_id, "LEGAL_REVIEW"
                    ): LEGAL_KEY,
                    calendar_review_key_name(candidate_id): CALENDAR_KEY,
                }
            )

    def _regulatory_observation(
        self,
        root: Path,
        candidate_id: str = "phillip-fx",
    ) -> dict[str, object]:
        (root / "fsa-registry.pdf").write_bytes(
            b"official-fsa-registry-fixture-kanto-kinsho-127"
        )
        manifest = {
            "schema_version": REGULATORY_SOURCE_MANIFEST_SCHEMA_VERSION,
            "candidate_id": candidate_id,
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
                    "observed_at_utc": "2026-07-21T10:00:00Z",
                    "source_file": "fsa-registry.pdf",
                }
            ],
        }
        evidence = prepare_regulatory_evidence(
            self.candidates,
            self.templates[candidate_id],
            manifest,
            source_root=root,
            now_provider=lambda: NOW - timedelta(minutes=10),
        )
        approvals = []
        for index, role in enumerate(("COMPLIANCE_REVIEW", "LEGAL_REVIEW")):
            key_name = regulatory_review_key_name(candidate_id, role)
            approvals.append(
                sign_regulatory_approval(
                    evidence,
                    approver_id=f"{candidate_id}-{role.lower()}er",
                    approver_role=role,
                    key_id=key_name,
                    signing_key=self.keys[key_name],
                    now_provider=lambda index=index: NOW
                    - timedelta(minutes=8 - index),
                )
            )
        return assemble_regulatory_observation(
            evidence,
            approvals,
            self.candidates,
            approval_key_provider=self.keys.get,
            now_provider=lambda: NOW,
            template=self.templates[candidate_id],
        )

    def _discovery(
        self,
        candidate_id: str = "phillip-fx",
    ) -> dict[str, object]:
        template = self.templates[candidate_id]
        receipt = discovery_receipt(
            candidate_id=candidate_id,
            company="Phillip Securities Japan, Ltd.",
            server="PhillipSecuritiesJP-PROD",
            required_symbols=tuple(template["broker_symbols"]),
            broker_symbols=dict(template["broker_symbols"]),
        )
        return _resign_discovery(
            receipt,
            leverage={"phillip-fx": 25, "phillip-commodity": 20}[candidate_id],
        )

    def _pack(
        self,
        candidate_id: str = "phillip-fx",
    ) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as regulatory_directory:
            regulatory = self._regulatory_observation(
                Path(regulatory_directory), candidate_id
            )
        with tempfile.TemporaryDirectory() as calendar_directory:
            _, _, calendar_review = approved_review(
                Path(calendar_directory), candidate_id
            )
        return build_registration_activation_review_pack(
            candidate_id=candidate_id,
            candidate_config=self.candidates,
            profile_config=self.profiles,
            template=self.templates[candidate_id],
            discovery=self._discovery(candidate_id),
            regulatory_observation=regulatory,
            calendar_review=calendar_review,
            discovery_signing_key=DISCOVERY_KEY,
            regulatory_key_provider=self.keys.get,
            calendar_key_provider=self.keys.get,
            git_identity={
                "clean": True,
                "commit_sha": "a" * 40,
                "tree_sha": "b" * 40,
            },
            now_provider=lambda: NOW,
        )

    def test_valid_pack_is_non_mutating_and_contains_only_three_bounded_diffs(self) -> None:
        original_candidates = deepcopy(self.candidates)
        original_profiles = deepcopy(self.profiles)
        original_template = deepcopy(self.template)

        pack = self._pack()
        verify_registration_activation_review_pack(pack)

        self.assertEqual(original_candidates, self.candidates)
        self.assertEqual(original_profiles, self.profiles)
        self.assertEqual(original_template, self.template)
        self.assertFalse(pack["configuration_mutated"])
        self.assertFalse(pack["registration_enabled"])
        self.assertTrue(pack["manual_activation_required"])
        self.assertEqual("DISABLED", pack["apply_capability"])
        self.assertEqual("DISABLED", pack["order_capability"])
        self.assertEqual(3, len(pack["proposed_files"]))
        for proposed_file in pack["proposed_files"]:
            self.assertEqual(
                proposed_file["before_sha256"],
                canonical_sha256(proposed_file["base_content"]),
            )
            self.assertEqual(
                proposed_file["after_sha256"],
                canonical_sha256(proposed_file["proposed_content"]),
            )

        profile_file = next(
            item
            for item in pack["proposed_files"]
            if item["path"] == "config/broker_evidence_profiles.v1.json"
        )
        selected = next(
            item
            for item in profile_file["proposed_content"]["profiles"]
            if item["candidate_id"] == "phillip-fx"
        )
        self.assertTrue(selected["registration_enabled"])
        self.assertEqual(PROPOSED_REGISTRATION_STATUS, selected["status"])

    def test_wrong_discovery_regulatory_or_calendar_key_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as regulatory_directory:
            regulatory = self._regulatory_observation(
                Path(regulatory_directory)
            )
        with tempfile.TemporaryDirectory() as calendar_directory:
            _, _, calendar_review = approved_review(
                Path(calendar_directory), "phillip-fx"
            )
        base = dict(
            candidate_id="phillip-fx",
            candidate_config=self.candidates,
            profile_config=self.profiles,
            template=self.template,
            discovery=self._discovery(),
            regulatory_observation=regulatory,
            calendar_review=calendar_review,
            discovery_signing_key=DISCOVERY_KEY,
            regulatory_key_provider=self.keys.get,
            calendar_key_provider=self.keys.get,
            git_identity={
                "clean": True,
                "commit_sha": "a" * 40,
                "tree_sha": "b" * 40,
            },
            now_provider=lambda: NOW,
        )
        bad_cases = (
            {"discovery_signing_key": b"x" * 40},
            {"regulatory_key_provider": lambda _: b"y" * 40},
            {"calendar_key_provider": lambda _: b"z" * 40},
            {"calendar_key_provider": lambda _: DISCOVERY_KEY},
        )
        for change in bad_cases:
            with self.subTest(change=tuple(change)), self.assertRaises(
                RegistrationActivationError
            ):
                build_registration_activation_review_pack(**{**base, **change})

    def test_dirty_base_or_already_enabled_profile_fails_closed(self) -> None:
        with self.assertRaisesRegex(RegistrationActivationError, "clean"):
            build_registration_activation_review_pack(
                **{
                    **self._valid_arguments(),
                    "git_identity": {
                        "clean": False,
                        "commit_sha": "a" * 40,
                        "tree_sha": "b" * 40,
                    },
                }
            )

        profile = deepcopy(self.profiles)
        profile["profiles"][0]["registration_enabled"] = True
        with self.assertRaisesRegex(RegistrationActivationError, "disabled"):
            build_registration_activation_review_pack(
                **{**self._valid_arguments(), "profile_config": profile}
            )

    def _valid_arguments(self) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as regulatory_directory:
            regulatory = self._regulatory_observation(
                Path(regulatory_directory)
            )
        with tempfile.TemporaryDirectory() as calendar_directory:
            _, _, calendar_review = approved_review(
                Path(calendar_directory), "phillip-fx"
            )
        return {
            "candidate_id": "phillip-fx",
            "candidate_config": self.candidates,
            "profile_config": self.profiles,
            "template": self.template,
            "discovery": self._discovery(),
            "regulatory_observation": regulatory,
            "calendar_review": calendar_review,
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

    def test_commodity_pack_is_independent_and_cross_lane_review_is_rejected(self) -> None:
        commodity = self._pack("phillip-commodity")
        verify_registration_activation_review_pack(commodity)
        self.assertEqual("phillip-commodity", commodity["candidate_id"])
        self.assertIn(
            "config/phillip_commodity_calendar_window_01.template.json",
            {item["path"] for item in commodity["proposed_files"]},
        )

        arguments = self._valid_arguments()
        arguments["candidate_id"] = "phillip-commodity"
        arguments["template"] = self.templates["phillip-commodity"]
        arguments["discovery"] = self._discovery("phillip-commodity")
        with self.assertRaises(RegistrationActivationError):
            build_registration_activation_review_pack(**arguments)

    def test_static_verifier_detects_pack_and_proposed_diff_tampering(self) -> None:
        pack = self._pack()
        mutations = []

        unsafe = deepcopy(pack)
        unsafe["order_capability"] = "ENABLED"
        unsafe["proposal_sha256"] = canonical_sha256(
            {key: value for key, value in unsafe.items() if key != "proposal_sha256"}
        )
        mutations.append(unsafe)

        extra_change = deepcopy(pack)
        profile_file = next(
            item
            for item in extra_change["proposed_files"]
            if item["path"] == "config/broker_evidence_profiles.v1.json"
        )
        profile_file["proposed_content"]["max_lot"] = 0.02
        profile_file["after_sha256"] = canonical_sha256(
            profile_file["proposed_content"]
        )
        extra_change["proposal_sha256"] = canonical_sha256(
            {
                key: value
                for key, value in extra_change.items()
                if key != "proposal_sha256"
            }
        )
        mutations.append(extra_change)

        wrong_path = deepcopy(pack)
        wrong_path["proposed_files"][0]["path"] = "config/other.json"
        wrong_path["proposal_sha256"] = canonical_sha256(
            {
                key: value
                for key, value in wrong_path.items()
                if key != "proposal_sha256"
            }
        )
        mutations.append(wrong_path)

        forged_base = deepcopy(pack)
        candidate_file = next(
            item
            for item in forged_base["proposed_files"]
            if item["path"] == "config/broker_candidates.phase3.json"
        )
        for content_name in ("base_content", "proposed_content"):
            candidate = next(
                item
                for item in candidate_file[content_name]["candidates"]
                if item["candidate_id"] == "phillip-fx"
            )
            candidate["server"] = "Forged-Demo"
        candidate_file["before_sha256"] = canonical_sha256(
            candidate_file["base_content"]
        )
        candidate_file["after_sha256"] = canonical_sha256(
            candidate_file["proposed_content"]
        )
        forged_base["proposal_sha256"] = canonical_sha256(
            {
                key: value
                for key, value in forged_base.items()
                if key != "proposal_sha256"
            }
        )
        mutations.append(forged_base)

        for mutation in mutations:
            with self.subTest(), self.assertRaises(RegistrationActivationError):
                verify_registration_activation_review_pack(mutation)

    def test_writer_is_create_exclusive(self) -> None:
        pack = self._pack()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "activation-review.json"
            write_registration_activation_review_pack_exclusive(output, pack)
            self.assertTrue(output.is_file())
            with self.assertRaises(FileExistsError):
                write_registration_activation_review_pack_exclusive(output, pack)


if __name__ == "__main__":
    unittest.main()
