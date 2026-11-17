from datetime import date

from pydantic import BaseModel


class Usage(BaseModel):
    input_tokens: int
    cached_input_tokens: int
    output_tokens: int
    estimated_usd: float | None = None
    pricing_date: date | None = None


def measure_usage(model: str, input_tokens: int, cached: int, output_tokens: int) -> Usage:
    usage = Usage(input_tokens=input_tokens, cached_input_tokens=cached, output_tokens=output_tokens)
    if model == "gpt-6-luna" and input_tokens <= 272_000 and 0 <= cached <= input_tokens:
        usage.estimated_usd = round(
            ((input_tokens - cached) * 0.10 + cached * 0.01 + output_tokens * 0.50) / 1_000_000, 9
        )
        usage.pricing_date = date(2026, 11, 17)
    return usage


class TraceEvent(BaseModel):
    finding_id: int | None
    operation: str
    outcome: str
    duration_ms: float


class Trace(BaseModel):
    events: list[TraceEvent]
    model_usage: list[Usage]
