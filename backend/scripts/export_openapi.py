"""Write the OpenAPI document to a file without a database or a .env file.

Usage: python scripts/export_openapi.py <output path>
"""

import json
import os
import sys
from pathlib import Path

# Set before the app is imported. The values are placeholders; nothing connects anywhere.
os.environ["APP_ENV"] = "development"
os.environ["CLIENT_ID_HASH_KEY"] = "openapi-export-placeholder"
os.environ["URL_INTEL_PROVIDER"] = "none"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: export_openapi.py <output path>")
    from app.core.config import get_settings
    from app.main import create_app

    get_settings.cache_clear()
    document = create_app().openapi()
    text = json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    with open(sys.argv[1], "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


if __name__ == "__main__":
    main()
