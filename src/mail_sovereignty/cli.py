import asyncio
from pathlib import Path


def preprocess() -> None:
    import argparse

    from mail_sovereignty.preprocess import run

    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=0, help="Only scan first N municipalities (0=all)")
    args = parser.parse_args()
    asyncio.run(run(Path("data.json"), limit=args.limit or None))


def postprocess() -> None:
    from mail_sovereignty.postprocess import run

    asyncio.run(run(Path("data.json")))


def validate() -> None:
    from mail_sovereignty.validate import run

    run(Path("data.json"), Path("."), quality_gate=True)
