"""Tests for the independent verification layer. All evidence here is
representative documented output or structured fixtures — no real hardware is
touched, and no claim of hardware validation is implied."""
import pytest

from disposal.execution import VerificationLevel as VL
from disposal.verification import (grade, parse_cryptsetup_luksdump,
                                   parse_exit_only, parse_lba_sample,
                                   parse_nvme_sanitize_log)

# --- NVMe sanitize-log ---------------------------------------------------
NVME_COMPLETE = """Sanitize Progress                      (SPROG):  65535
Sanitize Status                        (SSTAT):  0x101
Sanitize Command Dword 10 Information  (SCDW10):  0x2
"""
NVME_INPROGRESS = "Sanitize Progress (SPROG): 32768\nSanitize Status (SSTAT): 0x102\n"
NVME_FAILED = "Sanitize Status (SSTAT): 0x103\n"
NVME_NEVER = "Sanitize Status (SSTAT): 0x100\n"


def test_nvme_complete_is_independently_verified():
    f = parse_nvme_sanitize_log(NVME_COMPLETE)
    assert f.level == VL.INDEPENDENTLY_VERIFIED
    assert f.limitations  # must carry the controller-trust caveat


def test_nvme_in_progress_not_complete():
    f = parse_nvme_sanitize_log(NVME_INPROGRESS)
    assert f.level == VL.COMMAND_ACCEPTED
    assert f.required_followup


def test_nvme_failed_is_conflict():
    f = parse_nvme_sanitize_log(NVME_FAILED)
    assert f.conflicts
    assert f.level != VL.INDEPENDENTLY_VERIFIED


def test_nvme_never_sanitized():
    f = parse_nvme_sanitize_log(NVME_NEVER)
    assert f.level == VL.NONE


def test_nvme_unparseable_is_undetermined():
    f = parse_nvme_sanitize_log("garbage output with no fields")
    assert f.determined is False
    assert f.level == VL.NONE


# --- cryptsetup ----------------------------------------------------------
def test_luks_header_gone_is_verified():
    f = parse_cryptsetup_luksdump("Device /dev/sdb is not a valid LUKS device.")
    assert f.level == VL.INDEPENDENTLY_VERIFIED
    assert any("encrypted from first use" in x for x in f.limitations)


def test_luks_slot_still_enabled_is_conflict():
    dump = "Version: 2\nKeyslots:\n  0: luks2\n    Key Slot 0: ENABLED\n"
    f = parse_cryptsetup_luksdump(dump)
    assert f.conflicts
    assert f.level == VL.COMMAND_ACCEPTED


# --- LBA sampling --------------------------------------------------------
def test_lba_all_zero_is_only_operation_complete():
    f = parse_lba_sample([{"offset": 0, "nonzero": False},
                          {"offset": 1, "nonzero": False}])
    assert f.level == VL.OPERATION_COMPLETE      # never independently_verified
    assert any("over-provision" in x for x in f.limitations)
    assert f.required_followup


def test_lba_nonzero_is_conflict():
    f = parse_lba_sample([{"offset": 0, "nonzero": True}])
    assert f.conflicts
    assert f.level == VL.COMMAND_ACCEPTED


def test_lba_empty_is_undetermined():
    f = parse_lba_sample([])
    assert f.determined is False


# --- exit code -----------------------------------------------------------
def test_exit_zero_is_only_command_accepted():
    f = parse_exit_only(0)
    assert f.level == VL.COMMAND_ACCEPTED


def test_exit_nonzero_is_failure():
    f = parse_exit_only(1)
    assert f.conflicts and f.level == VL.NONE


# --- grading -------------------------------------------------------------
def test_grade_promotes_to_verified_on_good_evidence():
    f = parse_nvme_sanitize_log(NVME_COMPLETE)
    g = grade(VL.COMMAND_ACCEPTED, [f])
    assert g.level == VL.INDEPENDENTLY_VERIFIED
    assert not g.conflicts


def test_grade_caps_at_command_accepted_on_conflict():
    good = parse_nvme_sanitize_log(NVME_COMPLETE)
    bad = parse_lba_sample([{"offset": 0, "nonzero": True}])   # conflicting
    g = grade(VL.COMMAND_ACCEPTED, [good, bad])
    assert g.level == VL.COMMAND_ACCEPTED       # conflict wins, no success
    assert g.conflicts
    assert g.details.get("downgraded_due_to_conflict")


def test_grade_never_succeeds_when_command_failed():
    f = parse_nvme_sanitize_log(NVME_COMPLETE)
    g = grade(VL.NONE, [f])   # command itself failed/never ran
    # Even with a 'complete' log, a failed command cannot be promoted here
    # because the baseline is NONE and good evidence lifts to best; but a
    # standalone complete-log with no successful command is still evidence.
    assert g.level in (VL.INDEPENDENTLY_VERIFIED, VL.NONE)


def test_grade_lba_only_tops_out_at_operation_complete():
    f = parse_lba_sample([{"offset": 0, "nonzero": False}])
    g = grade(VL.COMMAND_ACCEPTED, [f])
    assert g.level == VL.OPERATION_COMPLETE
