"""Guards for test-suite conventions."""

from pathlib import Path


def test_asyncio_marker_used_only_with_async_tests():
    root = Path(__file__).resolve().parents[2]
    failures = []

    for path in (root / "tests").rglob("test_*.py"):
        lines = path.read_text(encoding="utf-8").splitlines()
        pending_asyncio_marker = False

        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped == "@pytest.mark.asyncio":
                pending_asyncio_marker = True
                continue

            if not pending_asyncio_marker:
                continue

            # Ignore blank lines and stacked decorators.
            if not stripped or stripped.startswith("@"):
                continue

            if stripped.startswith("async def test"):
                pending_asyncio_marker = False
                continue

            if stripped.startswith("def test"):
                rel = path.relative_to(root)
                failures.append(f"{rel}:{lineno} uses @pytest.mark.asyncio on sync test")
                pending_asyncio_marker = False
                continue

            # Any non-decorator line ends the association window.
            pending_asyncio_marker = False

    assert not failures, "Asyncio marker misuse found:\n" + "\n".join(failures)
