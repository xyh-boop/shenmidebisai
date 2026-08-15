"""在隔离虚拟环境中安装本项目 wheel, 并执行 CLI 基础 smoke。"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> None:
    root = Path.cwd()
    distribution = Path(sys.argv[1]).resolve() if len(sys.argv) == 2 else root / "dist"
    wheels = sorted(distribution.glob("aegisflow-*.whl"))
    if len(wheels) != 1:
        raise SystemExit(f"期望恰好一个 wheel, 实际找到 {len(wheels)} 个")

    environment = Path(tempfile.mkdtemp(prefix="aegisflow-wheel-smoke-"))
    try:
        subprocess.run([sys.executable, "-m", "venv", str(environment)], check=True)
        python = environment / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
        executable = environment / (
            "Scripts/aegisflow.exe" if sys.platform == "win32" else "bin/aegisflow"
        )
        requirements = environment / "requirements.txt"
        subprocess.run(
            [
                "uv",
                "export",
                "--format",
                "requirements.txt",
                "--all-extras",
                "--locked",
                "--no-emit-project",
                "--output-file",
                str(requirements),
            ],
            cwd=root,
            check=True,
        )
        subprocess.run(
            ["uv", "pip", "install", "--python", str(python), "--requirement", str(requirements)],
            cwd=root,
            check=True,
        )
        subprocess.run(
            [
                str(python),
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--no-deps",
                str(wheels[0]),
            ],
            check=True,
        )
        subprocess.run([str(executable), "doctor"], check=True)
        subprocess.run([str(executable), "rules", "--format", "table"], check=True)
    finally:
        shutil.rmtree(environment, ignore_errors=True)


if __name__ == "__main__":
    main()
