"""Circular / temporal statistics used by the behavioral profiler.

Sending-hour is naturally circular (23:00 is close to 01:00), so a plain arithmetic mean is
wrong. These helpers use the circular mean and angular distance instead.
"""
from __future__ import annotations

import math
from collections import Counter
from typing import Iterable, List, Optional, Sequence


def circular_hour_mean(hours: Sequence[float]) -> Optional[float]:
    """Mean hour-of-day in [0, 24) using the circular mean of hour angles."""
    hours = [h for h in hours if h is not None]
    if not hours:
        return None
    x = sum(math.cos(h * math.pi / 12.0) for h in hours)
    y = sum(math.sin(h * math.pi / 12.0) for h in hours)
    if abs(x) < 1e-12 and abs(y) < 1e-12:
        return None  # perfectly uniform / antipodal, mean undefined
    angle = math.atan2(y, x)
    return (angle * 12.0 / math.pi) % 24.0


def angular_hour_distance(a: Optional[float], b: Optional[float]) -> Optional[float]:
    """Shortest distance between two hours on a 24-hour clock, in hours (0..12)."""
    if a is None or b is None:
        return None
    diff = abs(a - b) % 24.0
    return min(diff, 24.0 - diff)


def hour_anomaly(current_hour: Optional[float], typical_hour: Optional[float]) -> float:
    """Normalised [0,1] anomaly of sending at ``current_hour``.

    12 hours away from the typical hour maps to 1.0; sending at the usual hour maps to 0.
    """
    distance = angular_hour_distance(current_hour, typical_hour)
    if distance is None:
        return 0.0
    return min(1.0, distance / 12.0)


def weekday_mode(weekdays: Sequence[int]) -> Optional[int]:
    if not weekdays:
        return None
    return int(Counter(weekdays).most_common(1)[0][0])


def weekday_anomaly(current_weekday: Optional[int], typical_weekday: Optional[int]) -> float:
    """0 when the weekday is the usual one, growing with circular day distance."""
    if current_weekday is None or typical_weekday is None:
        return 0.0
    diff = abs(int(current_weekday) - int(typical_weekday)) % 7
    distance = min(diff, 7 - diff)
    return min(1.0, distance / 3.0)
