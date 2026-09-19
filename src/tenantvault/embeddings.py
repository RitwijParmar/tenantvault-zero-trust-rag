from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from itertools import pairwise


class HashingEmbedder:
    """Deterministic 96-dim demo embedding; swap behind this interface in production."""

    dimensions = 96

    def embed(self, text: str) -> list[float]:
        tokens = re.findall(r"[a-z0-9]{2,}", text.lower())
        features = tokens + [f"{left}_{right}" for left, right in pairwise(tokens)]
        vector = [0.0] * self.dimensions
        for feature, weight in Counter(features).items():
            hashed = hashlib.blake2s(feature.encode(), digest_size=8).digest()
            slot = int.from_bytes(hashed[:4], "big") % self.dimensions
            sign = 1 if hashed[4] & 1 else -1
            vector[slot] += sign * (1.0 + math.log(weight))
        norm = math.sqrt(sum(value * value for value in vector)) or 1.0
        return [value / norm for value in vector]


def cosine_similarity(left: list[float], right: list[float]) -> float:
    return sum(a * b for a, b in zip(left, right))
