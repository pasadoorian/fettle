import pytest
import os

# Belt-and-suspenders: never let a test trigger the sudo re-exec path.
os.environ["FETTLE_TEST"] = "1"

# Real `snap list --all` output: core20 kept a superseded revision after a refresh
# (1974 active, 2015 disabled) and firefox left one behind too. Shared because snap
# pruning lives on the base backend and every distro's clean path is checked against
# the same bytes.
SNAP_LIST_ALL = ("Name Version Rev Tracking Publisher Notes\n"
                 "core20 20230622 1974 latest/stable canonical base\n"
                 "core20 20230801 2015 latest/stable canonical disabled\n"
                 "firefox 117.0 3026 latest/stable mozilla disabled\n")


@pytest.fixture(autouse=True)
def _reset_snap_probe():
    """`util.snap_ready()` caches per process — deliberately, because on a wedged host
    the probe costs a real timeout and three call sites would each pay it. A
    process-global cache leaks between tests: one test that resolved it to False left
    every later snap test skipping its own subject, which passed in isolation and failed
    in the suite. Reset before each test, never in production."""
    from fettle import util
    util._reset_snap_probe()
    yield
