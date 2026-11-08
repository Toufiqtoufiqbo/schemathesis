import time

from flask import request

import schemathesis
from schemathesis.engine import events
from schemathesis.engine.run import PhaseName
from test.apps.catalog.openapi.sign_up import sign_up_and_login
from test.utils import EventStream


def test_setup_runs_once_before_testing(ctx):
    api = ctx.openapi.apps.success()
    stream = EventStream(schemathesis.openapi.from_url(api.schema_url), phases=[PhaseName.FUZZING], max_examples=1)
    assert [event.phase.name for event in stream.execute().find_all(events.PhaseStarted)] == [
        PhaseName.SETUP,
        PhaseName.EXAMPLES,
        PhaseName.COVERAGE,
        PhaseName.FUZZING,
        PhaseName.STATEFUL_TESTING,
    ]


def test_setup_does_not_sign_up_after_the_time_budget_runs_out(app_runner):
    api = sign_up_and_login()
    paths = []

    # Slow probes spend the whole budget before sign-up gets its turn.
    @api.server.before_request
    def record_and_delay_probes():
        paths.append(request.path)
        if "X-Schemathesis-Probe" in request.headers:
            time.sleep(2)

    schema = schemathesis.openapi.from_dict(api.spec)
    schema.config.update(base_url=f"http://127.0.0.1:{app_runner.run_flask_app(api.server)}")
    EventStream(schema, phases=[PhaseName.FUZZING], max_time=1).execute()
    assert "/auth/register" not in paths
