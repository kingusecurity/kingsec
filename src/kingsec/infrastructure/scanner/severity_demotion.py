"""Shared severity-demotion logic for scanners whose classification is
otherwise purely path/status-based (ffuf, gobuster) - Phase 2B-c Priority 1b.

Defect 3 (docs/E2E-EVIDENCE-PHASE2B.md): a 200 on /.env returning 9KB of
generic Angular HTML scored identically to a real leaked credentials file,
because severity came only from the URL string and status code. Two signals
correct this, both STRICTLY DOWNGRADE-ONLY (never raise a severity above
what path/status-only classification assigned):

    Signal 1 (content-type mismatch, ffuf only - see ffuf_parser.py):
        a sensitive-path match whose response Content-Type is HTML/markup
        is almost never a real file disclosure.

    Signal 2 (baseline-shape clustering, this module - both scanners):
        among the findings that would otherwise score MEDIUM or higher,
        if a large cluster shares the exact same (status, length) shape,
        that shape is very likely one generic catch-all response repeated
        across many distinct paths, not that many distinct real findings.

The downgrade-only invariant is what makes an aggressive threshold safe: a
false trigger costs one severity level on a finding still reported with its
evidence intact, never a lost finding.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from kingsec.domain import Severity

# Phase 2B-c Priority 1b (approved plan, Change 2): a realistic large flood
# (e.g. a 4,600-result batch where 900 results share the baseline shape,
# 19.6%) must trigger. >=20% of the whole batch was too lenient and would
# have missed exactly that case. 3% of 4,600 is 138 - a genuine cluster of
# that many distinct real leaked files would be extraordinary; the
# downgrade-only design makes an aggressive bar safe (see module docstring).
_MIN_DOMINANT_SHAPE_OCCURRENCES = 5
_MIN_DOMINANT_SHAPE_FRACTION = 0.03


@dataclass(frozen=True)
class ShapeCandidate:
    """One result eligible for baseline-shape-clustering consideration.

    ``base_severity`` is the severity path/status-only classification (no
    demotion signal applied yet) would assign - the population this
    clustering check draws from is restricted to this value, never the
    already-demoted severity, per the approved design ("compute the
    dominant shape across only those findings that would otherwise score
    MEDIUM or HIGHER - not the whole batch").
    """

    index: int
    status: int
    length: int
    base_severity: Severity


def compute_baseline_shape_demotions(candidates: list[ShapeCandidate], total_results: int) -> frozenset[int]:
    """Return the ``index`` values that should be demoted under Signal 2.

    Args:
        candidates: One entry per otherwise-MEDIUM-or-higher result in the
            batch (results that would already be filtered out as LOW/
            INFORMATIONAL are noise for this purpose and must not be
            passed in - most results on a well-behaved server are
            identical-length 404s that were never candidates anyway).
        total_results: The size of the FULL batch (every result the
            scanner produced, not just the candidates) - the percentage
            threshold is of the whole scan, matching the approved
            worked example (138 / 4,600 = 3%).

    Returns:
        The ``index`` of every candidate whose (status, length) matches
        the dominant shape, when that shape clears both thresholds.
        Empty when there are no candidates, or the dominant shape doesn't
        clear the bar.
    """
    if not candidates or total_results <= 0:
        return frozenset()

    shape_counts: Counter[tuple[int, int]] = Counter((c.status, c.length) for c in candidates)
    dominant_shape, dominant_count = shape_counts.most_common(1)[0]

    if dominant_count < _MIN_DOMINANT_SHAPE_OCCURRENCES:
        return frozenset()
    if (dominant_count / total_results) < _MIN_DOMINANT_SHAPE_FRACTION:
        return frozenset()

    return frozenset(c.index for c in candidates if (c.status, c.length) == dominant_shape)
