import re

import pytest

from auditor.utils.cvss import (
    VECTOR_PATTERN, base_score, format_vector, parse_vector, severity_rating,
)

@pytest.mark.parametrize("vector, score", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),   # classic unauthenticated RCE
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),   # reflected XSS
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),   # local privilege escalation
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9),   # scope change with low privileges
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),   # unauthenticated data disclosure
    ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),   # no impact
])
def test_base_score_matches_reference_values(vector, score):
    assert base_score(parse_vector(vector)) == score

def test_parse_vector_accepts_missing_prefix_case_and_extra_metrics():
    metrics = parse_vector(" av:n/ac:l/pr:n/ui:n/s:u/c:h/i:h/a:h/E:P ")

    assert format_vector(metrics) == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

@pytest.mark.parametrize("vector", [
    "",
    None,
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",          # missing A
    "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",      # invalid value
    "CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", # duplicate metric
    "high",
])
def test_parse_vector_rejects_invalid(vector):
    assert parse_vector(vector) is None

@pytest.mark.parametrize("score, rating", [
    (0.0, "none"), (0.1, "low"), (3.9, "low"), (4.0, "medium"), (6.9, "medium"),
    (7.0, "high"), (8.9, "high"), (9.0, "critical"), (10.0, "critical"),
])
def test_severity_rating(score, rating):
    assert severity_rating(score) == rating

def test_vector_pattern_matches_formatted_vectors():
    vector = format_vector(parse_vector("AV:A/AC:H/PR:L/UI:R/S:C/C:L/I:N/A:H"))
    assert re.fullmatch(VECTOR_PATTERN, vector)
