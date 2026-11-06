"""CVSS v3.1 base score calculation, following the FIRST specification (section 7)."""
import math
import re

BASE_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
# Privileges Required weighs more when the scope changes.
_PR_WEIGHTS = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.5},
}
_SCOPES = {"U", "C"}

VECTOR_PATTERN = r"^CVSS:3\.1/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[HLN]/I:[HLN]/A:[HLN]$"


def parse_vector(vector: str) -> dict[str, str] | None:
    """Parses a CVSS 3.x base vector (the 'CVSS:3.x/' prefix is optional) into {metric: value}.

    Returns None unless all eight base metrics are present exactly once with valid values.
    Temporal/environmental metrics, if present, are ignored.
    """
    text = re.sub(r"\s+", "", str(vector or "")).upper()
    text = re.sub(r"^CVSS:3\.[01]/", "", text)
    if not text:
        return None

    metrics: dict[str, str] = {}
    for part in text.split("/"):
        key, sep, value = part.partition(":")
        if not sep:
            return None
        if key in BASE_METRICS:
            if key in metrics:
                return None
            metrics[key] = value

    if set(metrics) != set(BASE_METRICS):
        return None
    if metrics["S"] not in _SCOPES or metrics["PR"] not in _PR_WEIGHTS["U"]:
        return None
    if any(metrics[k] not in weights for k, weights in _WEIGHTS.items()):
        return None
    return metrics


def format_vector(metrics: dict[str, str]) -> str:
    return "CVSS:3.1/" + "/".join(f"{k}:{metrics[k]}" for k in BASE_METRICS)


def _roundup(value: float) -> float:
    """The spec's Roundup: smallest one-decimal number >= value, robust to float error."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def base_score(metrics: dict[str, str]) -> float:
    scope_changed = metrics["S"] == "C"
    iss = 1 - ((1 - _WEIGHTS["C"][metrics["C"]])
               * (1 - _WEIGHTS["I"][metrics["I"]])
               * (1 - _WEIGHTS["A"][metrics["A"]]))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = (8.22 * _WEIGHTS["AV"][metrics["AV"]] * _WEIGHTS["AC"][metrics["AC"]]
                      * _PR_WEIGHTS[metrics["S"]][metrics["PR"]] * _WEIGHTS["UI"][metrics["UI"]])

    if impact <= 0:
        return 0.0
    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10))
    return _roundup(min(impact + exploitability, 10))


def severity_rating(score: float) -> str:
    """Qualitative rating; 0.0 is 'none'."""
    if score == 0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"
