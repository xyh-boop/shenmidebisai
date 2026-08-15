"""将 uv 的 CycloneDX 导出规范化为可重复提交的 SBOM。"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path


def _stable_timestamp() -> str:
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    return datetime.fromtimestamp(epoch, UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def normalize(path: Path) -> None:
    document = json.loads(path.read_text(encoding="utf-8"))
    metadata = document.setdefault("metadata", {})
    metadata["timestamp"] = _stable_timestamp()

    # serialNumber 和 timestamp 是 uv 的非确定性元数据; 组件、版本、关系和哈希保持原样。
    identity = copy.deepcopy(document)
    identity.pop("serialNumber", None)
    identity.get("metadata", {}).pop("timestamp", None)
    canonical = json.dumps(identity, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    document["serialNumber"] = f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, digest)}"
    path.write_text(json.dumps(document, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("用法: python normalize_sbom.py <sbom.cdx.json>")
    normalize(Path(sys.argv[1]))
