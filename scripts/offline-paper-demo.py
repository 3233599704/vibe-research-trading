"""Run the hermetic offline PAPER demonstration."""

from __future__ import annotations

from pathlib import Path
import sys


sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from research.strategy_lab.offline_paper_demo import (  # noqa: E402
    OfflinePaperDemoError,
    _run_demo,
    _run_qmt_compat_demo,
    canonical_json_line,
    failure_document,
)


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    qmt_compat = arguments == ["--broker", "QMT_COMPAT_SANDBOX"]
    if arguments and not qmt_compat:
        print(
            canonical_json_line(
                failure_document(
                    OfflinePaperDemoError(
                        "ARGUMENT_ERROR",
                        "offline demo accepts no arguments",
                    )
                )
            )
        )
        return 2
    try:
        result = _run_qmt_compat_demo() if qmt_compat else _run_demo()
    except Exception as exc:  # stable CLI boundary; no traceback or paths
        print(
            canonical_json_line(
                failure_document(
                    exc,
                    broker="QMT_COMPAT_SANDBOX" if qmt_compat else None,
                )
            )
        )
        return 2
    print(canonical_json_line(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
