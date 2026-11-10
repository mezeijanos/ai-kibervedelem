"""Stream PE-report features from sources/data2/*.txt into one CSV file.

The files in sources/data2 are text reports, not PE binaries.  This script reads one
report at a time, so it is suitable for tens of thousands of reports without
loading the whole dataset into memory.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from pathlib import Path
from typing import Any, Iterator


# Environment variables make the locations configurable in scheduled jobs and
# other automation.  Without them, use the directory from which Python was
# launched, rather than the directory that contains this script.
WORKING_DIR = Path.cwd()
DEFAULT_INPUT_DIR = Path(
    os.environ.get("DATA2_INPUT_DIR", WORKING_DIR / "sources" / "data2")
)
DEFAULT_OUTPUT_PATH = Path(
    os.environ.get(
        "DATA2_OUTPUT_PATH", WORKING_DIR / "result" / "data2_features.csv"
    )
)

# The two identifiers make the output traceable back to the source report;
# the remaining columns are the ten features requested for the dataset.
CSV_COLUMNS = (
    "SourceFile",
    "FileSHA256",
    "FileSize",
    "FileEntropy",
    "NumberOfSections",
    "SectionEntropy",
    "SectionCharacteristics",
    "SizeOfCode",
    "EntryPointSection",
    "ImportedDLLCount",
    "NumberOfImportedFunctions",
    "ImportName",
)

SINGLE_VALUE_KEYS = {
    "FileSHA256": "FileSHA256",
    "FileSize": "FileSize",
    "FileEntropy": "FileEntropy",
    "NumberOfSections": "NumberOfSections",
    "SizeOfCode": "SizeOfCode",
    "EntryPointSection": "EntryPointSection",
    "ImportedDLLCount": "ImportedDLLCount",
    "Number of imported functions": "NumberOfImportedFunctions",
}


def value_as_number_when_possible(value: str) -> int | float | str:
    """Keep malformed values visible while converting normal numeric values."""
    try:
        return int(value)
    except ValueError:
        try:
            return float(value)
        except ValueError:
            return value


def parse_report(report_path: Path, input_dir: Path) -> dict[str, Any]:
    """Extract requested fields from one text report using one streaming pass."""
    row: dict[str, Any] = {column: "" for column in CSV_COLUMNS}
    row["SourceFile"] = report_path.relative_to(input_dir).as_posix()

    section_characteristics: list[dict[str, Any]] = []
    section_entropies: list[dict[str, Any]] = []
    import_names: list[str] = []
    seen_import_names: set[str] = set()
    current_section_name: str | None = None
    current_feature_section_name: str | None = None

    # errors="replace" prevents one malformed byte sequence from stopping an
    # otherwise valid 38k-file extraction job.
    with report_path.open("r", encoding="utf-8", errors="replace") as report:
        for raw_line in report:
            key, separator, value = raw_line.strip().partition(":")
            if not separator:
                continue
            value = value.strip()

            if key in SINGLE_VALUE_KEYS:
                row[SINGLE_VALUE_KEYS[key]] = value_as_number_when_possible(value)
            elif key == "SectionName":
                current_section_name = value
            elif key == "FeatureSectionName":
                current_feature_section_name = value
            elif key == "SectionCharacteristics":
                section_characteristics.append(
                    {
                        "name": current_section_name,
                        "value": value_as_number_when_possible(value),
                    }
                )
            elif key == "SectionEntropy":
                section_entropies.append(
                    {
                        "name": current_feature_section_name,
                        "value": value_as_number_when_possible(value),
                    }
                )
            elif key == "ImportName" and value and value != "N/A":
                # A function can occur through more than one import table;
                # retain first-seen order but do not duplicate a CSV feature.
                if value not in seen_import_names:
                    import_names.append(value)
                    seen_import_names.add(value)

    # JSON preserves variable-length, ordered features safely inside CSV cells.
    row["SectionEntropy"] = json.dumps(
        section_entropies, ensure_ascii=False, separators=(",", ":")
    )
    row["SectionCharacteristics"] = json.dumps(
        section_characteristics, ensure_ascii=False, separators=(",", ":")
    )
    row["ImportName"] = json.dumps(
        import_names, ensure_ascii=False, separators=(",", ":")
    )
    return row


def iter_report_paths(input_dir: Path) -> Iterator[Path]:
    """Yield reports incrementally; report contents are never accumulated."""
    for directory, subdirectories, filenames in os.walk(input_dir):
        subdirectories.sort()
        for filename in sorted(filenames):
            if filename.lower().endswith(".txt"):
                yield Path(directory) / filename


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT_DIR,
        help=(
            "folder containing report files "
            f"(default: {DEFAULT_INPUT_DIR}; set DATA2_INPUT_DIR to override)"
        ),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
        help=(
            "CSV destination "
            f"(default: {DEFAULT_OUTPUT_PATH}; set DATA2_OUTPUT_PATH to override)"
        ),
    )
    parser.add_argument(
        "--progress-every",
        type=int,
        default=1_000,
        help="print progress after this many reports (default: 1000)",
    )
    parser.add_argument(
        "--flush-every",
        type=int,
        default=1_000,
        help="flush the partial CSV after this many rows (default: 1000)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="process at most this many reports; useful for a small test run",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="replace an existing output CSV or partial CSV",
    )
    args = parser.parse_args()

    if args.progress_every <= 0 or args.flush_every <= 0:
        parser.error("--progress-every and --flush-every must be positive")
    if args.limit is not None and args.limit <= 0:
        parser.error("--limit must be positive")
    return args


def main() -> int:
    args = parse_arguments()
    input_dir = args.input.resolve()
    output_path = args.output.resolve()
    partial_path = output_path.with_suffix(output_path.suffix + ".part")

    if not input_dir.is_dir():
        print(f"Input directory does not exist: {input_dir}", file=sys.stderr)
        return 2
    if output_path.exists() and not args.overwrite:
        print(
            f"Output already exists: {output_path}. Use --overwrite to replace it.",
            file=sys.stderr,
        )
        return 2
    if partial_path.exists() and not args.overwrite:
        print(
            f"Partial output already exists: {partial_path}. "
            "Inspect it or use --overwrite to replace it.",
            file=sys.stderr,
        )
        return 2

    output_path.parent.mkdir(parents=True, exist_ok=True)
    processed = 0
    written = 0
    failed = 0

    try:
        with partial_path.open("w", newline="", encoding="utf-8") as output_file:
            writer = csv.DictWriter(output_file, fieldnames=CSV_COLUMNS)
            writer.writeheader()

            for report_path in iter_report_paths(input_dir):
                if args.limit is not None and processed >= args.limit:
                    break
                processed += 1
                try:
                    writer.writerow(parse_report(report_path, input_dir))
                    written += 1
                except OSError as error:
                    failed += 1
                    print(f"Skipping {report_path}: {error}", file=sys.stderr)

                if processed % args.flush_every == 0:
                    output_file.flush()
                if processed % args.progress_every == 0:
                    print(
                        f"Processed {processed:,}; wrote {written:,}; failed {failed:,}",
                        file=sys.stderr,
                    )
    except OSError as error:
        print(f"Could not write {partial_path}: {error}", file=sys.stderr)
        return 1

    # The complete result appears only after the final rename. A readable
    # .part file is left behind if the run is interrupted or fails.
    try:
        partial_path.replace(output_path)
    except OSError as error:
        print(f"Could not finalize {output_path}: {error}", file=sys.stderr)
        return 1

    print(
        f"Done. Processed {processed:,}; wrote {written:,}; failed {failed:,}.\n"
        f"CSV: {output_path}",
        file=sys.stderr,
    )
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
