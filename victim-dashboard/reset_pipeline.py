import argparse
import shutil
from pathlib import Path


TARGET_DIRS = [
    "pcap_done",
    "pcap_error",
    "pcap_inbox",
    "pcap_spool",
    "flow_outputs",
]


def clear_directory_contents(directory: Path) -> tuple[int, int]:
    files_removed = 0
    dirs_removed = 0

    if not directory.exists():
        directory.mkdir(parents=True, exist_ok=True)
        return files_removed, dirs_removed

    for child in directory.iterdir():
        if child.is_dir():
            shutil.rmtree(child)
            dirs_removed += 1
        else:
            child.unlink(missing_ok=True)
            files_removed += 1

    return files_removed, dirs_removed


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Clear pipeline folders (pcap_done, pcap_error, pcap_inbox, pcap_spool, flow_outputs)."
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip confirmation prompt and clean immediately.",
    )
    args = parser.parse_args()

    base_dir = Path(__file__).resolve().parent
    abs_dirs = [base_dir / name for name in TARGET_DIRS]

    print("The following folders will be emptied:")
    for d in abs_dirs:
        print(f" - {d}")

    if not args.yes:
        answer = input("Proceed? Type 'yes' to continue: ").strip().lower()
        if answer != "yes":
            print("Aborted. No changes made.")
            return

    total_files = 0
    total_dirs = 0
    for d in abs_dirs:
        files_removed, dirs_removed = clear_directory_contents(d)
        total_files += files_removed
        total_dirs += dirs_removed

    print(f"Done. Removed {total_files} files and {total_dirs} directories.")


if __name__ == "__main__":
    main()
