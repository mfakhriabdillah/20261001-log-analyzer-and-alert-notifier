```python
"""
Log Analyzer and Alert Notifier
A CLI tool for cloud/DevOps log analysis, pattern detection, and alerting.
"""

import argparse
import csv
import io
import json
import logging
import os
import re
import sys
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Generator, Optional

logger = logging.getLogger("loganalyzer")

# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------

@dataclass
class LogEntry:
    """Parsed representation of a single log line."""
    timestamp: datetime
    level: str
    message: str
    source_file: str = ""
    raw_line: str = ""
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "level": self.level,
            "message": self.message,
            "source_file": self.source_file,
            "raw_line": self.raw_line,
        }


@dataclass
class Alert:
    """An alert triggered by threshold evaluation."""
    alert_id: str
    severity: str
    rule_name: str
    condition: str
    current_value: float
    threshold: float
    message: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class MetricsResult:
    """Aggregated metrics from a log analysis pass."""
    total_lines: int = 0
    parsed_lines: int = 0
    errors: int = 0
    warnings: int = 0
    info: int = 0
    debug: int = 0
    other: int = 0
    top_errors: list = field(default_factory=list)
    top_sources: list = field(default_factory=list)
    rate_per_minute: float = 0.0
    time_range_start: Optional[str] = None
    time_range_end: Optional[str] = None
    alerts: list = field(default_factory=list)

    def summary(self) -> str:
        lines = [
            "=" * 60,
            "LOG ANALYSIS REPORT",
            "=" * 60,
            f"Total Lines:      {self.total_lines}",
            f"Parsed Lines:     {self.parsed_lines}",
            f"Unparsed Lines:   {self.total_lines - self.parsed_lines}",
            "",
            "--- Severity Breakdown ---",
            f"ERROR:   {self.errors}",
            f"WARNING: {self.warnings}",
            f"INFO:    {self.info}",
            f"DEBUG:   {self.debug}",
            f"OTHER:   {self.other}",
            "",
        ]
        if self.time_range_start:
            lines.append("--- Time Range ---")
            lines.append(f"Start: {self.time_range_start}")
            lines.append(f"End:   {self.time_range_end}")
            lines.append(f"Rate:  {self.rate_per_minute:.2f} lines/min")
            lines.append("")
        if self.top_errors:
            lines.append("--- Top Error Patterns ---")
            for i, (pattern, count) in enumerate(self.top_errors[:10], 1):
                lines.append(f"  {i}. [{count:>5}x] {pattern}")
            lines.append("")
        if self.top_sources:
            lines.append("--- Top Source Files ---")
            for i, (src, count) in enumerate(self.top_sources[:10], 1):
                lines.append(f"  {i}. [{count:>5}x] {src}")
            lines.append("")
        if self.alerts:
            lines.append("--- Alerts ---")
            for a in self.alerts:
                lines.append(f"  [{a.severity.upper()}] {a.rule_name}: {a.condition} -> {a.current_value} (threshold: {a.threshold})")
            lines.append("")
        lines.append("=" * 60)
        return "\n".join(lines)

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, default=str)

    def to_csv(self) -> str:
        rows = []
        rows.append(["metric", "value"])
        rows.append(["total_lines", self.total_lines])
        rows.append(["parsed_lines", self.parsed_lines])
        rows.append(["errors", self.errors])
        rows.append(["warnings", self.warnings])
        rows.append(["info", self.info])
        rows.append(["debug", self.debug])
        rows.append(["rate_per_minute", round(self.rate_per_minute, 2)])
        rows.append(["alerts_generated", len(self.alerts)])
        return "\n".join([",".join(str(c) for c in r) for r in rows])


# ---------------------------------------------------------------------------
# Log Parser
# ---------------------------------------------------------------------------

# Common log timestamp formats
_LOG_PATTERNS: list[tuple[str, re.Pattern]] = [
    # ISO 8601  —  2024-01-15T10:30:00Z or 2024-01-15T10:30:00+00:00
    (
        r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s*"
        r"(?P<level>TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)\s*:?"+
        r"(?P<msg>.*)",
        re.IGNORECASE,
    ),
    # Syslog-ish  —  Jan 15 10:30:00
    (
        r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+"
        r"(?P<pid>\S+?)(?:\[\d+\])?\s*"
        r"(?:(?P<level>TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)\s*:?"+
        r"?P<msg>.*)",
        re.IGNORECASE,
    ),
    # Bracket date  —  [2024-01-15 10:30:00]
    (
        r"\[(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:[,\.]\d+)?)\]\s*"
        r"(?P<level>TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)\s*-?\s*"
        r"(?P<msg>.*)",
        re.IGNORECASE,
    ),
    # Slash date  —  2024/01/15 10:30:00
    (
        r"(?P<ts>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}(?:[,.]\d+)?)\s*"
        r"(?P<level>TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)\s*:?"+
        r"(?P<msg>.*)",
        re.IGNORECASE,
    ),
]

_TS_FORMATS = [
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%d %H:%M:%S,%f",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y/%m/%d %H:%M:%S,%f",
    "%Y/%m/%d %H:%M:%S",
]

# Fallback: extract level + message without timestamp
_FALLBACK_LEVEL_RE = re.compile(
    r"\b(?P<level>TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)\b",
    re.IGNORECASE,
)

# User-supplied custom pattern
_CUSTOM_PATTERN = re.compile(
    r"(?P<ts>[^:]+):\s*(?P<level>\w+)\s*:\s*(?P<msg>.*)"
)


def _parse_timestamp(raw: str) -> Optional[datetime]:
    raw = raw.strip()
    for fmt in _TS_FORMATS:
        try:
            dt = datetime.strptime(raw, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


class LogParser:
    """
    Parses log files using multiple built-in formats and a user-provided
    custom regex. Falls back to level-only extraction when no timestamp matches.
    """

    def __init__(self, custom_pattern: Optional[str] = None):
        self.custom_re: Optional[re.Pattern] = None
        if custom_pattern:
            try:
                self.custom_re = re.compile(custom_pattern, re.IGNORECASE)
                logger.info("Custom regex pattern loaded: %s", custom_pattern)
            except re.error as exc:
                raise ValueError(f"Invalid custom regex: {exc}") from exc

    def parse_file(self, filepath: str) -> Generator[LogEntry, None, None]:
        """Yield LogEntry objects from *filepath*."""
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {filepath}")
        if not path.is_file():
            raise IsADirectoryError(f"Expected a file, got directory: {filepath}")

        logger.debug("Parsing file: %s", filepath)
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for lineno, raw_line in enumerate(fh, 1):
                raw_line = raw_line.rstrip("\n\r")
                if not raw_line.strip():
                    continue
                entry = self._parse_line(raw_line, filepath, lineno)
                if entry:
                    yield entry

    def _parse_line(self, line: str, source: str, lineno: int) -> Optional[LogEntry]:
        # Try user custom pattern first
        if self.custom_re:
            m = self.custom_re.match(line)
            if m:
                return LogEntry(
                    timestamp=_parse_timestamp(m.group("ts")) or datetime.now(timezone.utc),
                    level=m.group("level").upper(),
                    message=m.group("msg").strip(),
                    source_file=source,
                    raw_line=line,
                    extra={"lineno": lineno},
                )

        # Try built-in patterns
        for pat_name, pat in _LOG_PATTERNS:
            m = pat.match(line)
            if m:
                ts = _parse_timestamp(m.group("ts"))
                level = m.group("level").upper().replace("WARNING", "WARN")
                msg = m.group("msg").strip() if "msg" in m.groupdict() else ""
                return LogEntry(
                    timestamp=ts or datetime.now(timezone.utc),
                    level=level,
                    message=msg,
                    source_file=source,
                    raw_line=line,
                    extra={"lineno": lineno},
                )

        # Fallback: level-only
        m = _FALLBACK_LEVEL_RE.search(line)
        if m:
            return LogEntry(
                timestamp=datetime.now(timezone.utc),
                level=m.group("level").upper().replace("WARNING", "WARN"),
                message=line.strip(),
                source_file=source,
                raw_line=line,
                extra={"lineno": lineno, "parsed": False},
            )

        # Line has no recognizable level — skip
        return None


# ---------------------------------------------------------------------------
# Metric Aggregator
# ---------------------------------------------------------------------------

class MetricAggregator:
    """
    Computes statistics over an iterable of LogEntry objects and evaluates
    alert rules against computed thresholds.
    """

    def __init__(
        self,
        error_threshold: int = 10,
        warning_threshold: int = 50,
        rate_threshold: float = 1000.0,
        custom_rules: Optional[list[dict]] = None,
    ):
        self.error_threshold = error_threshold
        self.warning_threshold = warning_threshold
        self.rate_threshold = rate_threshold
        self.custom_rules = custom_rules or []
        self._error_counter: Counter = Counter()
        self._source_counter: Counter = Counter()
        self._timestamps: list[datetime] = []

    def ingest(self, entries: Generator[LogEntry, None, None]) -> MetricsResult:
        """Ingest entries and return a MetricsResult."""
        counts = {"ERROR": 0, "WARN": 0, "INFO": 0, "DEBUG": 0, "other": 0}
        total = 0

        for entry in entries:
            total += 1
            lvl = entry.level.upper()
            if lvl == "WARNING":
                lvl = "WARN"
            if lvl in counts:
                counts[lvl] += 1
            else:
                counts["other"] += 1
            if lvl in ("ERROR", "WARN", "FATAL", "CRITICAL"):
                self._error_counter[entry.message[:120]] += 1
            self._source_counter[entry.source_file] += 1
            if entry.timestamp:
                self._timestamps.append(entry.timestamp)

        # Time-range math
        sorted_ts = sorted(self._timestamps)
        if len(sorted_ts) >= 2:
            span_minutes = (sorted_ts[-1] - sorted_ts[0]).total_seconds() / 60.0
            rate = total / span_minutes if span_minutes > 0 else float(total)
            t_start = sorted_ts[0].isoformat()
            t_end = sorted_ts[-1].isoformat()
        else:
            rate = float(total)
            t_start = sorted_ts[0].isoformat() if sorted_ts else None
            t_end = t_start

        # Build alerts
        alerts = self._evaluate_alerts(counts, rate, total)

        return MetricsResult(
            total_lines=total,
            parsed_lines=total,
            errors=counts["ERROR"] + counts.get("FATAL", 0) + counts.get("CRITICAL", 0),
            warnings=counts["WARN"],
            info=counts["INFO"],
            debug=counts["DEBUG"],
            other=counts["other"],
            top_errors=self._error_counter.most_common(20),
            top_sources=self._source_counter.most_common(20),
            rate_per_minute=round(rate, 2),
            time_range_start=t_start,
            time_range_end=t_end,
            alerts=alerts,
        )

    def _evaluate_alerts(
        self, counts: dict, rate: float, total: int
    ) -> list[Alert]:
        alerts: list[Alert] = []
        now = datetime.now(timezone.utc)
        alert_idx = 0

        def _add(sev: str, rule: str, cond: str, cur: float, thresh: float):
            nonlocal alert_idx
            alert_idx += 1
            alerts.append(
                Alert(
                    alert_id=f"ALT-{alert_idx:04d}",
                    severity=sev,
                    rule_name=rule,
                    condition=cond,
                    current_value=cur,
                    threshold=thresh,
                    message=f"{rule}: {cond} ({cur} vs threshold {thresh})",
                    timestamp=now,
                )
            )

        if counts["ERROR"] > self.error_threshold:
            _add("critical", "High Error Count",
                 f"errors={counts['ERROR']}", counts["ERROR"], self.error_threshold)
        if counts["WARN"] > self.warning_threshold:
            _add("warning", "High Warning Count",
                 f"warnings={counts['WARN']}", counts["WARN"], self.warning_threshold)
        if rate > self.rate_threshold:
            _add("warning", "High Log Rate",
                 f"rate={rate:.1f}/min", rate, self.rate_threshold)

        for rule in self.custom_rules:
            key = rule.get("metric", "")
            op = rule.get("operator", ">")
            thresh = float(rule.get("threshold", 0))
            label = rule.get("label", key)
            sev = rule.get("severity", "warning")
            val = counts.get(key, 0)
            triggered = False
            if op == ">" and val > thresh:
                triggered = True
            elif op == ">=" and val >= thresh:
                triggered = True
            elif op == "<" and val < thresh:
                triggered = True
            elif op == "<=" and val <= thresh:
                triggered = True
            elif op == "==" and val == thresh:
                triggered = True
            if triggered:
                alert_idx += 1
                alerts.append(
                    Alert(
                        alert_id=f"ALT-{alert_idx:04d}",
                        severity=sev,
                        rule_name=label,
                        condition=f"{key}{op}{thresh}",
                        current_value=val,
                        threshold=thresh,
                        message=f"{label}: {key}{op}{thresh} => {val}",
                        timestamp=now,
                    )
                )

        return alerts


# ---------------------------------------------------------------------------
# Notifier
# ---------------------------------------------------------------------------

class Notifier:
    """
    Dispatches alerts through one or more channels.
    Supports stdout (default), JSON file, Slack webhook, and plain-text email
    body generation. In production, replace the stubs with real HTTP calls / SMTP.
    """

    def __init__(
        self,
        channel: str = "stdout",
        slack_webhook: Optional[str] = None,
        output_file: Optional[str] = None,
        include_details: bool = True,
    ):
        self.channel = channel
        self.slack_webhook = slack_webhook
        self.output_file = output_file
        self.include_details = include_details

    def notify(self, result: MetricsResult) -> None:
        if not result.alerts:
            logger.debug("No alerts to notify on.")
            return

        alerts_text = self._format_alerts(result)

        if self.channel in ("stdout", "all"):
            print("\n" + alerts_text)

        if self.channel in ("file", "all") and self.output_file:
            self._write_file(self.output_file, alerts_text)

        if self.channel == "slack" and self.slack_webhook:
            self._send_slack(alerts_text, result.alerts)

    def notify_report(self, result: MetricsResult) -> None:
        """Send full report (not just alerts)."""
        text = result.summary()
        if self.channel in ("stdout", "all"):
            print(text)
        if self.channel in ("file", "all") and self.output_file:
            self._write_file(self.output_file, text)

    # -- internal helpers -----------------------------------------------------

    def _format_alerts(self, result: MetricsResult) -> str:
        parts = [
            f"🚨 Log Analysis Alert — {result.alerts[0].timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Total lines analyzed: {result.total_lines}",
            f"Errors: {result.errors} | Warnings: {result.warnings}",
            "",
        ]
        for a in result.alerts:
            emoji = {"critical": "🔴", "warning": "🟡", "info": "🔵"}.get(a.severity, "⚪")
            parts.append(f"{emoji} [{a.severity.upper()}] {a.rule_name}")
            parts.append(f"   Condition: {a.condition}")
            parts.append(f"   Message:   {a.message}")
            if self.include_details and a.extra:
                parts.append(f"   Details:   {json.dumps(a.extra, default=str)}")
            parts.append("")
        return "\n".join(parts)

    def _write_file(self, path: str, text: str) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("a", encoding="utf-8") as fh:
            fh.write(text + "\n")
        logger.info("Alert report written to %s", path)

    def _send_slack(self, text: str, alerts: list[Alert]) -> None:
        """Stub — replaces a real POST to the Slack incoming webhook."""
        blocks = []
        for a in alerts:
            color = {"critical": "#FF0000", "warning": "#FFA500", "info": "#0066CC"}.get(
                a.severity, "#808080"
            )
            blocks.append(
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*{a.rule_name}* — {a.message}"},
                    "accessory": {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "View Details"},
                        "url": "#",
                        "action_id": f"alert_{a.alert_id}",
                    },
                }
            )
        payload = {
            "text": "Log Analyzer Alert",
            "blocks": blocks,
        }
        logger.info(
            "Slack payload (stub): %s", json.dumps(payload, indent=2)
        )
        # In production:
        # import urllib.request
        # req = urllib.request.Request(
        #     self.slack_webhook,
        #     data=json.dumps(payload).encode(),
        #     headers={"Content-Type": "application/json"},
        # )
        # urllib.request.urlopen(req, timeout=10)


# ---------------------------------------------------------------------------
# Filter helpers
# ---------------------------------------------------------------------------

def apply_time_filter(
    entries: Generator[LogEntry, None, None],
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
) -> Generator[LogEntry, None, None]:
    """Yield only entries whose timestamps fall within [since, until]."""
    for entry in entries:
        ts = entry.timestamp
        if ts is None:
            continue
        # Make tz-aware for comparison
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        if since and ts < since:
            continue
        if until and ts > until:
            continue
        yield entry


def apply_level_filter(
    entries: Generator[LogEntry, None, None],
    levels: list[str],
) -> Generator[LogEntry, None, None]:
    """Yield only entries whose level is in *levels*."""
    allowed = {lvl.upper() for lvl in levels}
    for entry in entries:
        lvl = entry.level.upper()
        if lvl == "WARNING":
            lvl = "WARN"
        if lvl in allowed:
            yield entry


def apply_search_filter(
    entries: Generator[LogEntry, None, None],
    pattern: str,
) -> Generator[LogEntry, None, None]:
    """Yield only entries whose raw line matches *pattern*."""
    re_pat = re.compile(pattern, re.IGNORECASE)
    for entry in entries:
        if re_pat.search(entry.raw_line):
            yield entry


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def analyze(
    input_paths: list[str],
    pattern: str,
    since: Optional[str],
    until: Optional[str],
    levels: list[str],
    search: Optional[str],
    output_fmt: str,
    custom_regex: Optional[str],
    error_threshold: int,
    warning_threshold: int,
    rate_threshold: float,
    custom_rules_json: Optional[str],
    notifier_channel: str,
    slack_webhook: Optional[str],
    output_file: Optional[str],
    verbose: bool,
) -> MetricsResult:
    """
    Main orchestration: parse → filter → aggregate → alert → output.
    """
    # Configure logging
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)-7s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Parse time window
    since_dt: Optional[datetime] = None
    until_dt: Optional[datetime] = None
    if since:
        since_dt = _parse_arg_datetime(since)
        if since_dt is None:
            raise ValueError(f"Cannot parse '--since' value: {since}")
    if until:
        until_dt = _parse_arg_datetime(until)
        if until_dt is None:
            raise ValueError(f"Cannot parse '--until' value: {until}")

    # Custom alert rules
    custom_rules: list[dict] = []
    if custom_rules_json:
        try:
            custom_rules = json.loads(custom_rules_json)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid --custom-rules JSON: {exc}") from exc

    # Build pipeline
    parser = LogParser(custom_pattern=custom_regex)

    def chained() -> Generator[LogEntry, None, None]:
        # Collect all source files
        all_files: list[str] = []
        for p in input_paths:
            path = Path(p)
            if path.is_file():
                all_files.append(str(path))
            elif path.is_dir():
                all_files.extend(
                    str(fp) for fp in path.rglob("*")
                    if fp.suffix in (".log", ".txt", "")
                )
            else:
                logger.warning("Skipping non-existent path: %s", p)
        if not all_files:
            raise FileNotFoundError(
                f"No log files found in any of: {input_paths}"
            )
        for fp in all_files:
            try:
                yield from parser.parse_file(fp)
            except Exception as exc:
                logger.error("Failed to parse %s: %s", fp, exc)

    pipeline = chained()

    # Apply filters
    if since_dt or until_dt:
        pipeline = apply_time_filter(pipeline, since=since_dt, until=until_dt)
    if levels:
        pipeline = apply_level_filter(pipeline, levels)
    if search:
        pipeline = apply_search_filter(pipeline, search)

    # Aggregate
    aggregator = MetricAggregator(
        error_threshold=error_threshold,
        warning_threshold=warning_threshold,
        rate_threshold=rate_threshold,
        custom_rules=custom_rules,
    )
    result = aggregator.ingest(pipeline)

    # Output
    notifier = Notifier(
        channel=notifier_channel,
        slack_webhook=slack_webhook,
        output_file=output_file,
    )

    if output_fmt == "text":
        notifier.notify_report(result)
    elif output_fmt == "json":
        print(result.to_json())
        notifier.notify(result)
    elif output_fmt == "csv":
        print(result.to_csv())
        notifier.notify(result)
    elif output_fmt == "entries":
        # Stream matching entries as JSON lines
        for entry in chained():
            # Re-run the same filters for entry output
            if since_dt and entry.timestamp and entry.timestamp < since_dt:
                continue
            if until_dt and entry.timestamp and entry.timestamp > until_dt:
                continue
            if levels:
                lvl = entry.level.upper().replace("WARNING", "WARN")
                allowed = {l.upper() for l in levels}
                if lvl not in allowed:
                    continue
            if search:
                if not re.search(search, entry.raw_line, re.IGNORECASE):
                    continue
            print(json.dumps(entry.to_dict()))
        notifier.notify(result)
    else:
        notifier.notify_report(result)

    # Notify alerts regardless of format
    notifier.notify(result)

    return result


def _parse_arg_datetime(value: str) -> Optional[datetime]:
    """Parse a user-supplied datetime string (flexible formats)."""
    for fmt in (
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%Y/%m/%d %H:%M:%S",
    ):
        try:
            dt = datetime.strptime(value, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    epilog = """\
examples:
  %(prog)s /var/log/syslog
  %(prog)s ./logs/ --since "2024-01-01" --until "2024-01-31" -l ERROR WARNING
  %(prog)s app.log --search "OutOfMemory" --output json
  %(prog)s ./logs/ --pattern access --rate-threshold 500
  %(prog)s app.log --custom-rule '{"metric":"errors","operator":">","threshold":5,"label":"Many errors"}' \
         --channel slack --slack-webhook "https://hooks.slack.com/..."
    """
    parser = argparse.ArgumentParser(
        prog="loganalyzer",
        description=(
            "Log Analyzer and Alert Notifier — parse, analyze, and alert on "
            "cloud/DevOps log files with support for multiple formats, "
            "time-window filtering, custom regex, and Slack integration."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=epilog,
    )

    # Positional / required
    parser.add_argument(
        "inputs",
        nargs="+",
        help="Log file(s) or directory to analyze. Directories are scanned "
             "recursively for *.log, *.txt, and extensionless files.",
    )

    # Analysis mode
    analysis = parser.add_argument_group("analysis options")
    analysis.add_argument(
        "--pattern", "-p",
        choices=["error", "warning", "info", "debug", "access", "syslog", "custom"],
        default="error",
        help="Predefined analysis pattern. 'error' focuses on errors/fatal; "
             "'access' treats the input as web-access logs; 'custom' requires "
             "--custom-regex. Defaults to 'error'.",
    )
    analysis.add_argument(
        "--custom-regex",
        help="User-supplied PCRE-style regex with named groups 'ts', 'level', 'msg'.",
    )
    analysis.add_argument(
        "--levels", "-l",
        nargs="+",
        choices=["trace", "debug", "info", "warn", "warning", "error", "fatal", "critical"],
        help="Only consider entries at these severity levels.",
    )
    analysis.add_argument(
        "--search", "-s",
        help="Further filter entries by a Python regex applied to the raw line.",
    )
    analysis.add_argument(
        "--since",
        help="Include entries at or after this datetime (ISO-like). Examples: "
             "'2024-01-15T10:00:00', '2024-01-01'.",
    )
    analysis.add_argument(
        "--until",
        help="Include entries up to and including this datetime.",
    )

    # Thresholds & alerting
    alerting = parser.add_argument_group("alerting options")
    alerting.add_argument(
        "--error-threshold",
        type=int,
        default=10,
        help="Trigger a critical alert when error count exceeds this value. Default: 10.",
    )
    alerting.add_argument(
        "--warning-threshold",
        type=int,
        default=50,
        help="Trigger a warning alert when warning count exceeds this value. Default: 50.",
    )
    alerting.add_argument(
        "--rate-threshold",
        type=float,
        default=1000.0,
        help="Trigger a warning alert when log rate exceeds N lines/min. Default: 1000.",
    )
    alerting.add_argument(
        "--custom-rule",
        action="append",
        metavar="JSON",
        help='Inline JSON alert rule, e.g. \'{"metric":"errors","operator":">",' \
             '"threshold":5,"label":"Many errors","severity":"critical"}\'. '
             "Can be specified multiple times. Known metrics: errors, warnings, "
             "info, debug, total_lines, rate_per_minute.",
    )

    # Output
    output = parser.add_argument_group("output options")
    output.add_argument(
        "--output", "-o",
        choices=["text", "json", "csv", "entries"],
        default="text",
        help="Output format. 'entries' prints each matching log line as a JSON "
             "object (useful for piping). Default: text.",
    )
    output.add_argument(
        "--output-file",
        metavar="PATH",
        help="Write the report/alerts to this file (appended).",
    )

    # Notifications
    notif = parser.add_argument_group("notification options")
    notif.add_argument(
        "--channel",
        choices=["stdout", "file", "slack", "all"],
        default="stdout",
        help="Where to send alert notifications. Default: stdout.",
    )
    notif.add_argument(
        "--slack-webhook",
        help="Slack incoming webhook URL for --channel slack/all.",
    )

    # Verbosity
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable DEBUG-level logging.",
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse and validate inputs without running full analysis.",
    )

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if getattr(args, "dry_run", False):
            logger.info("Dry run — validating inputs ...")
            for inp in args.inputs:
                p = Path(inp)
                if p.is_file():
                    lines = sum(1 for _ in p.open())
                    logger.info("  %s : %d lines", p, lines)
                elif p.is_dir():
                    files = list(p.rglob("*"))
                    logger.info("  %s : %d files found", p, len(files))
                else:
                    logger.warning("  %s : NOT FOUND", p)
            logger.info("Dry run complete.")
            return 0

        analyze(
            input_paths=args.inputs,
            pattern=args.pattern,
            since=args.since,
            until=args.until,
            levels=args.levels or [],
            search=args.search,
            output_fmt=args.output,
            custom_regex=args.custom_regex,
            error_threshold=args.error_threshold,
            warning_threshold=args.warning_threshold,
            rate_threshold=args.rate_threshold,
            custom_rules_json=json.dumps(args.custom_rule) if args.custom_rule else None,
            notifier_channel=args.channel,
            slack_webhook=args.slack_webhook,
            output_file=args.output_file,
            verbose=args.verbose,
        )
        return 0

    except FileNotFoundError as exc:
        logger.error(str(exc))
        return 1
    except ValueError as exc:
        logger.error("Configuration error: %s", exc)
        return 2
    except KeyboardInterrupt:
        logger.info("Interrupted by user.")
        return 130
    except Exception as exc:
        logger.exception("Unexpected error: %s", exc)
        return 255


if __name__ == "__main__":
    sys.exit(main())
```