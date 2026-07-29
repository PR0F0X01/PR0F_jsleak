# jsleak

## Description

**jsleak** is a fast and lightweight command-line tool for discovering **secrets** and **hidden endpoints** in JavaScript files.

It supports scanning one or multiple URLs concurrently, extracting JavaScript resources, detecting secrets using customizable YAML regex patterns, discovering hidden endpoints, checking endpoint status codes, and exporting results in a format optimized for large-scale security assessments.

The project was originally inspired by **LinkFinder**, while the secret detection patterns are compatible with **secrets-patterns-db** and any custom YAML pattern set.

---

## Features

* Detect API keys, access tokens, secrets, credentials, and other sensitive information.
* Discover hidden endpoints and URLs inside JavaScript.
* Automatic endpoint resolution (Complete URL mode).
* Concurrent scanning for high performance.
* HTTP status code checking.
* Support for custom YAML regex patterns.
* Results automatically sorted by:

  * URL
  * Pattern
  * Secret Value
* Automatic output splitting into multiple **Part** files for processing large datasets.
* Output format optimized for automated security workflows and AI agents.

---

## Latest Update

jsleak now supports regex patterns from **secrets-patterns-db**:

https://github.com/mazen160/secrets-patterns-db

Any compatible YAML pattern file can also be used.

Example:

```yaml
patterns:
  - pattern:
      name: Amazon MWS Auth Token
      regex: "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
      confidence: low
```

---

## Installation

Install the latest version:

```bash
go install github.com/PR0F0X01/PR0F_jsleak@latest
```

---
## New Options

### Split Output

Use `-p` to specify the maximum number of results written to each Part file.

Default:

```bash
-p 500
```

Example:

```bash
cat urls.txt | jsleak -t trufflehog-v3.yml -s -p 1000
```

---

### Output Directory

Use `-o` to specify the output directory.

Default:

```text
output/
```

Example:

```bash
cat urls.txt | jsleak -t trufflehog-v3.yml -s -o results
```

Generated structure:

```text
results/
└── parts/
    ├── part-1.txt
    ├── part-2.txt
    └── ...
```

## Usage

Choose a YAML pattern file.

For example:

```text
https://raw.githubusercontent.com/mazen160/secrets-patterns-db/refs/heads/master/datasets/trufflehog-v3.yml
```

Run Secret Finder:

```bash
echo "https://example.com" | jsleak -t trufflehog-v3.yml -s
```

Display help:

```bash
jsleak -h
```
- Configurable output splitting using the -p flag.
- Custom output directory using the -o flag.

### Secret Finder

```bash
echo https://example.com | jsleak -t trufflehog-v3.yml -s
```

### Link Finder

```bash
echo https://example.com | jsleak -l
```

### Complete URL

```bash
echo https://example.com | jsleak -e
```

### Check Status Code

```bash
echo https://example.com | jsleak -k
```

### Multiple Flags

```bash
echo https://example.com | jsleak -l -s
```

### Scan Multiple URLs

```bash
cat urls.txt | jsleak -l -s -c 30
```

---

## Secret Output Format

Secret results are automatically normalized and sorted:

```text
[https://example.com/app.js] [AWS Access Key] [AKIA...]
[https://example.com/app.js] [GitHub Token] [ghp_xxxxx]
[https://example.com/vendor.js] [Stripe Secret Key] [sk_live_xxxxx]
```

Results are sorted by:

1. URL
2. Pattern Name
3. Secret Value

making them easier to review manually or process automatically.

---

## Output Splitting

Large outputs can be automatically split into multiple files.

Example:

```text
parts/
├── part-1.txt
├── part-2.txt
├── part-3.txt
└── ...
```

Each file contains the configured maximum number of results, making them ideal for distributed processing and automation pipelines.

---

## To Do

* Scan secrets from discovered JavaScript endpoints automatically.
* Support local JavaScript file scanning.
* Support APK analysis.
* Improve endpoint discovery.
* Update regex database.
* Multiple User-Agent support.
* Colored output.
* JSON output mode.
* HTML report generation.

---

## Credits

Special thanks to the following projects:

* https://github.com/GerbenJavado/LinkFinder
* https://github.com/0xsha/GoLinkFinder
* https://github.com/mazen160/secrets-patterns-db
