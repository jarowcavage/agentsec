import re
from collections import Counter
from math import log, sqrt


def terms(text: str) -> Counter[str]:
    return Counter(re.findall(r"[a-z0-9]+", text.lower()))


class TfidfIndex:
    """Embed passages and queries into the same sparse, normalized vector space."""

    def __init__(self, documents: dict[str, str]):
        counts = {identifier: terms(text) for identifier, text in documents.items()}
        frequencies = Counter(token for vector in counts.values() for token in vector)
        self.weights = {
            token: 1 + log((1 + len(counts)) / (1 + count)) for token, count in frequencies.items()
        }
        self.documents = {identifier: self.vector(tokens) for identifier, tokens in counts.items()}

    def vector(self, counts: Counter[str]) -> dict[str, float]:
        weighted = {
            token: (1 + log(count)) * self.weights[token]
            for token, count in counts.items()
            if token in self.weights
        }
        magnitude = sqrt(sum(weight * weight for weight in weighted.values()))
        return {token: weight / magnitude for token, weight in weighted.items()}

    def search(self, query: str, *, limit: int) -> list[str]:
        vector = self.vector(terms(query))
        scores = {
            identifier: sum(value * document.get(token, 0) for token, value in vector.items())
            for identifier, document in self.documents.items()
        }
        ordered = sorted(scores, key=lambda identifier: (-scores[identifier], identifier))
        return [identifier for identifier in ordered if scores[identifier] > 0][:limit]
