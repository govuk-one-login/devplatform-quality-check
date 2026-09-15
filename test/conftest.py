from pathlib import Path

from checkov.cloudformation.runner import Runner

REPO_ROOT = Path(__file__).resolve().parent.parent


def run_check(fixture_file, check_id, check_dir=None):
    if check_dir is None:
        check_dir = REPO_ROOT / "src" / "checks"

    runner = Runner()
    result = runner.run(
        root_folder=None,
        files=[str(fixture_file)],
        external_checks_dir=[str(check_dir)],
    )
    passed = [r.check_id for r in result.passed_checks if r.check_id == check_id]
    failed = [r.check_id for r in result.failed_checks if r.check_id == check_id]
    return passed, failed
