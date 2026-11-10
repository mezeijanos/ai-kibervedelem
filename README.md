# PE Report Feature Extraction

This project converts text reports generated from Portable Executable (PE)
files into a CSV dataset for exploration and clustering.  It is designed for
large collections: the extractor processes one report at a time rather than
loading all reports into memory.

## Project contents

| Path | Purpose |
| --- | --- |
| [extract_data2_features.py](./extract_data2_features.py) | Streams report features from `.txt` files into a CSV. |
| [explore_extracted_features.ipynb](./explore_extracted_features.ipynb) | Notebook for exploring the extracted data. |
| [sources/peinfo2.yara](./sources/peinfo2.yara) | YARA rules associated with the PE-report workflow. |
| [requirements.txt](./requirements.txt) | Python dependencies for the notebook and clustering workflow. |

## Requirements

The feature extractor itself only uses the Python standard library.  The
notebook and cluster profiler require the packages listed in
`requirements.txt`.

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## Input format

Place report files anywhere below [sources/data2/](./sources/data2/).  The extractor recursively
processes files ending in `.txt`, keeping a relative `SourceFile` path for each
row.  Reports are expected to contain colon-separated fields such as
`FileSHA256`, `FileSize`, `SectionEntropy`, and `ImportName`.

Malformed lines are skipped, and invalid text bytes are replaced so that one
bad report does not stop a long run.

## Extract features

From the project root, extract the reports into the default result location:

```powershell
& .\.venv\Scripts\python.exe .\extract_data2_features.py `
  --output .\result\data2_features.csv
```

The command uses `./sources/data2` as the input folder when `--input` is omitted.  A
parent directory for the CSV is created automatically; the input folder must
already exist.

For a small validation run, add a limit:

```powershell
& .\.venv\Scripts\python.exe .\extract_data2_features.py `
  --limit 100 `
  --output .\result\sample_features.csv
```

Use `--overwrite` only when replacing an existing final CSV or its partial
counterpart is intentional:

```powershell
& .\.venv\Scripts\python.exe .\extract_data2_features.py `
  --output .\result\data2_features.csv `
  --overwrite
```

Run `--help` for all options:

```powershell
& .\.venv\Scripts\python.exe .\extract_data2_features.py --help
```

### Default locations and environment overrides

Defaults are based on the directory where the command is launched, not the
directory holding the script.  For example, when launched from `D:\work`, the
default input and output locations are `D:\work\sources\data2` and
`D:\work\result\data2_features.csv`.

Set either environment variable for automation or a different dataset:

```powershell
$env:DATA2_INPUT_DIR = "D:\datasets\pe-reports"
$env:DATA2_OUTPUT_PATH = "D:\outputs\pe_features.csv"
& .\.venv\Scripts\python.exe .\extract_data2_features.py
```

Explicit `--input` and `--output` options take precedence over their
environment-variable defaults.

## Output CSV

Each row represents one source report.  The output columns are:

```text
SourceFile, FileSHA256, FileSize, FileEntropy, NumberOfSections,
SectionEntropy, SectionCharacteristics, SizeOfCode, EntryPointSection,
ImportedDLLCount, NumberOfImportedFunctions, ImportName
```

`SectionEntropy`, `SectionCharacteristics`, and `ImportName` contain compact
JSON arrays inside their CSV cells.  Section entries preserve their source
section name and numeric value; imported function names keep first-seen order
and are de-duplicated.

The extractor writes to `<output>.part` while processing.  It renames that
file to the requested CSV only after a complete run, leaving an inspectable
partial file if the run is interrupted.

## Explore the result

Open [explore_extracted_features.ipynb](./explore_extracted_features.ipynb)
from the project root after creating `result/data2_features.csv`. Its first
cell loads that path before preparing the exploratory plots and clustering
analysis.
