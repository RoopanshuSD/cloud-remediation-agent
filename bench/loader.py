"""Load RemediationBench tasks from bench/tasks/<name>/.

Task layout:
    task.toml        metadata: name, family, difficulty, fault (root-cause label), decoy
    instruction.md   the ticket the agent sees (symptoms only)
    setup.py         setup(cloud): plants the fault in a fresh account
    verify.py        verify(toolbox) -> {check_name: bool}; HIDDEN from the agent, run after it finishes
    solution.py      solve(call): reference fix, used to prove the task is solvable
"""
from __future__ import annotations

import importlib.util
import tomllib
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType

TASKS_DIR = Path(__file__).resolve().parent / "tasks"


def _module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@dataclass
class Task:
    name: str
    path: Path
    meta: dict
    instruction: str
    setup: ModuleType
    verifier: ModuleType
    solution: ModuleType

    @property
    def fault(self) -> str:
        return self.meta["fault"]

    @property
    def family(self) -> str:
        return self.meta["family"]


def load_task(path: Path) -> Task:
    path = Path(path)
    meta = tomllib.loads((path / "task.toml").read_text(encoding="utf-8"))
    key = path.name.replace("-", "_")
    return Task(meta["name"], path, meta, (path / "instruction.md").read_text(encoding="utf-8"),
                _module(path / "setup.py", f"rb_{key}_setup"), _module(path / "verify.py", f"rb_{key}_verify"),
                _module(path / "solution.py", f"rb_{key}_solution"))


def load_tasks(root: Path = TASKS_DIR, only: list[str] | None = None) -> list[Task]:
    dirs = sorted(p for p in Path(root).iterdir() if (p / "task.toml").exists())
    return [load_task(p) for p in dirs if not only or p.name in only]
