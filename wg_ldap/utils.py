from __future__ import annotations

import logging
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Iterable, List


log = logging.getLogger(__name__)


def atomic_write(path: str | os.PathLike[str], content: str, mode: int = 0o640) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", delete=False, dir=str(target.parent)) as tf:
        tf.write(content)
        tmp_name = tf.name
    os.chmod(tmp_name, mode)
    os.replace(tmp_name, target)


def run_cmd(cmd: Iterable[str], input: str | None = None, capture_output: bool = False) -> subprocess.CompletedProcess:
    cmd_list: List[str] = list(cmd)
    log.debug("Running command: %s", " ".join(cmd_list))
    res = subprocess.run(cmd_list, capture_output=capture_output, text=True, input=input)
    if res.returncode != 0:
        raise RuntimeError(
            f"Command failed ({res.returncode}): {' '.join(cmd_list)}\nSTDOUT: {res.stdout}\nSTDERR: {res.stderr}"
        )
    if res.stdout:
        log.debug("stdout: %s", res.stdout.strip())
    if res.stderr:
        log.debug("stderr: %s", res.stderr.strip())
    return res
