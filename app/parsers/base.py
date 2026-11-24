"""Base classes and shared result types for NetLog AI log parsers."""

from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass, field

from app.schemas import NormalizedLogRecord


@dataclass
class ParseResult:
    """Outcome of parsing a batch of raw log lines."""

    records: list[NormalizedLogRecord] = field(default_factory=list)
    bad_line_count: int = 0
    total_lines: int = 0
    bad_line_samples: list[str] = field(default_factory=list)
    format_detected: str = "unknown"


class BaseParser(ABC):
    """Abstract base class for format-specific log parsers."""

    format_name: str = "base"

    @abstractmethod
    def can_parse(self, line: str) -> bool:
        """Return True if this parser recognizes the format of the given line."""

    @abstractmethod
    def parse_line(self, line: str) -> NormalizedLogRecord | None:
        """Parse a single raw log line into a NormalizedLogRecord, or None if invalid."""

    def parse_lines(self, lines: Iterable[str], max_bad_samples: int = 10) -> ParseResult:
        """Parse an iterable of raw log lines, counting bad lines without raising."""
        result = ParseResult(format_detected=self.format_name)
        for raw_line in lines:
            stripped = raw_line.strip()
            if not stripped:
                continue
            result.total_lines += 1
            record = self.parse_line(stripped)
            if record is None:
                result.bad_line_count += 1
                if len(result.bad_line_samples) < max_bad_samples:
                    result.bad_line_samples.append(stripped[:200])
            else:
                result.records.append(record)
        return result
