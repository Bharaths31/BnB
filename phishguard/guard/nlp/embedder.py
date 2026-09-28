"""Security-domain embedding encoder.

The interface (``embed(text) -> np.ndarray``) is preserved so the rest of the system is
unchanged. Until the real SecureBERT ONNX artifact is exported, this returns a **deterministic**
feature-hash embedding rather than random noise: the same text always yields the same vector.
That keeps similarity features reproducible and testable, which the random placeholder did not.
"""
from __future__ import annotations

import hashlib
import re
from typing import List

import numpy as np

EMBEDDING_DIM = 768
_TOKEN_RE = re.compile(r"[a-z0-9@._\-]+")


class Embedder:
    def __init__(self, dim: int = EMBEDDING_DIM):
        # The real implementation loads the SecureBERT ONNX session here:
        #   self.session = onnxruntime.InferenceSession(settings.models['security_encoder'])
        self.dim = dim
        self.ready = True

    def _tokens(self, text: str) -> List[str]:
        return _TOKEN_RE.findall((text or "").lower())

    def embed(self, text: str) -> np.ndarray:
        """Deterministic bag-of-token hashing embedding, L2-normalised."""
        vec = np.zeros(self.dim, dtype=np.float32)
        tokens = self._tokens(text)
        if not tokens:
            return vec
        for token in tokens:
            digest = hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
            idx = int.from_bytes(digest[:4], "little") % self.dim
            sign = 1.0 if digest[4] & 1 else -1.0
            vec[idx] += sign
        norm = float(np.linalg.norm(vec))
        if norm > 0:
            vec /= norm
        return vec


embedder = Embedder()
