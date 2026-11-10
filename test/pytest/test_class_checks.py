import pathlib

import pytest

_ALWAYS_FAIL_CHECK = """
@schemathesis.check
class AlwaysFail:
    def after_run(self, ctx):
        raise AssertionError("always fails in after_run")
"""


@pytest.mark.parametrize(
    "test_body",
    [
        """
lazy_schema = schemathesis.pytest.from_fixture("simple_schema")

@lazy_schema.parametrize()
def test_api(case):
    pass
""",
        """
@schema.parametrize()
def test_api(case):
    pass
""",
        """
@schemathesis.pytest.parametrize(simple=schema)
def test_api(case):
    pass
""",
    ],
    ids=["from_fixture", "schema_parametrize", "pytest_parametrize"],
)
def test_after_run_failure_reported(testdir, test_body):
    testdir.make_test(_ALWAYS_FAIL_CHECK + test_body)
    result = testdir.runpytest()
    result.assert_outcomes(passed=1)
    assert result.ret != 0
    result.stdout.fnmatch_lines(["*- ST901 Custom check failed: `AlwaysFail`*", "*    always fails in after_run*"])


_SCHEMA_PARAMETRIZE_BODY = """
@schema.parametrize()
def test_api(case):
    pass
"""


def test_after_run_skipped_on_collect_only(testdir):
    testdir.make_test(_ALWAYS_FAIL_CHECK + _SCHEMA_PARAMETRIZE_BODY)
    result = testdir.runpytest("--collect-only")
    # No tests ran, so after_run checks must not run and must not fail the session.
    assert result.ret == 0, result.stdout.str()


_SEEN_OPERATIONS_CHECK = """
@schemathesis.check
class SeenOperations:
    def __init__(self):
        self.seen = set()

    def after_response(self, ctx, response, case):
        self.seen.add(case.operation.label)

    def after_run(self, ctx):
        if {raise_when_seen} and self.seen:
            raise AssertionError("seen: " + ", ".join(sorted(self.seen)))
"""


@pytest.mark.parametrize(
    ("raise_when_seen", "exit_code", "expected_lines"),
    [
        (True, 1, ["*- ST901 Custom check failed: `SeenOperations`*", "*    seen: *POST /users/*"]),
        (False, 0, ["*= 1 passed in *"]),
    ],
    ids=["failing", "passing"],
)
def test_after_run_for_state_machine(ctx, testdir, raise_when_seen, exit_code, expected_lines):
    api = ctx.openapi.apps.users_crud()
    testdir.make_test(
        _SEEN_OPERATIONS_CHECK.format(raise_when_seen=raise_when_seen)
        + f"""
schema = schemathesis.openapi.from_url("{api.schema_url}")
schema.config.update(base_url="{api.base_url}")
schema.config.checks.update(included_check_names=["SeenOperations"])
TestCase = schema.as_state_machine().TestCase
TestCase.settings = settings(max_examples=2, stateful_step_count=2, deadline=None, derandomize=True)
"""
    )
    result = testdir.runpytest()
    result.assert_outcomes(passed=1)
    assert result.ret == exit_code
    result.stdout.fnmatch_lines(expected_lines)


def test_after_run_failure_reported_without_terminal(testdir):
    testdir.make_test(_ALWAYS_FAIL_CHECK + _SCHEMA_PARAMETRIZE_BODY)
    result = testdir.runpytest("-p", "no:terminal")
    assert result.ret != 0
    # Failure text must still surface without the terminal reporter, not be silently dropped.
    assert "always fails in after_run" in (result.stderr.str() + result.stdout.str())


def test_after_run_fires_once_per_test_function(testdir):
    counter_path = str(testdir.tmpdir.join("after_run_count.txt"))
    testdir.make_test(
        f"""
import pathlib
pathlib.Path(r{counter_path!r}).write_text("0")

@schemathesis.check
class Counter:
    def after_run(self, ctx):
        p = pathlib.Path(r{counter_path!r})
        p.write_text(str(int(p.read_text() or 0) + 1))

lazy_schema = schemathesis.pytest.from_fixture("simple_schema")

@lazy_schema.parametrize()
def test_one(case):
    pass

@lazy_schema.parametrize()
def test_two(case):
    pass
"""
    )
    result = testdir.runpytest("-v")
    result.assert_outcomes(passed=2)
    assert result.ret == 0
    assert int(pathlib.Path(counter_path).read_text()) == 2


def test_after_run_failure_alongside_failed_test(testdir):
    testdir.make_test(
        _ALWAYS_FAIL_CHECK
        + """
@schema.parametrize()
def test_api(case):
    raise AssertionError("test body fails")
"""
    )
    result = testdir.runpytest()
    result.assert_outcomes(failed=1)
    assert result.ret == 1
    result.stdout.fnmatch_lines(["*- ST901 Custom check failed: `AlwaysFail`*", "*    always fails in after_run*"])
