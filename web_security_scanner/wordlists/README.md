# Wordlists

Enumeration inputs for the crawler / web mapper. **Not** injection signatures —
those live in [`../PAYLOAD/data/`](../PAYLOAD/data/).

| file | used by | notes |
|---|---|---|
| `subdomains.json` | `modules/web_mapper_async._discover_from_dns` | bounded DNS brute-force labels |
| `directories.json` | (future) content-discovery | common path segments |

Load through the helper, which dedupes and fails soft:

```python
from web_security_scanner.wordlists import load_wordlist
labels = load_wordlist("subdomains", limit=50)
```

Moved here from `PAYLOAD/` in v5.1 (`subdominios.json` → `subdomains.json`,
`subdirectorios.json` → `directories.json`).
