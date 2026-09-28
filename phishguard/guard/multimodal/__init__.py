"""Cross-modal consistency engine (WS2)."""
from guard.multimodal.consistency import (
    FEATURE_NAMES,
    ConsistencyResult,
    MultimodalComponent,
    build_result,
    compute_consistency,
)
from guard.multimodal.identity_consistency import (
    claimed_brands,
    confusable_distance,
    edit_distance,
    is_lookalike,
)

__all__ = [
    "MultimodalComponent",
    "ConsistencyResult",
    "compute_consistency",
    "build_result",
    "FEATURE_NAMES",
    "claimed_brands",
    "edit_distance",
    "confusable_distance",
    "is_lookalike",
]
