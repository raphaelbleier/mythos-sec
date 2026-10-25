from mythos.state import CoverageMatrix, TaskTree, Task
from mythos.selection import select_tools, classify


def test_coverage_matrix_marks_and_summarizes():
    cov = CoverageMatrix()
    cov.ensure("http://t/a")
    cov.mark("http://t/a", "sqli", "tested")
    cov.mark("http://t/a", "sqli", "finding")
    assert cov.cells["http://t/a"]["sqli"] == "finding"
    s = cov.summary()
    assert s["endpoints"] == 1 and s["findings"] == 1


def test_coverage_no_downgrade():
    cov = CoverageMatrix()
    cov.mark("http://t/a", "sqli", "finding")
    cov.mark("http://t/a", "sqli", "tested")   # must not overwrite a finding
    assert cov.cells["http://t/a"]["sqli"] == "finding"


def test_task_tree_transitions_are_logged():
    tt = TaskTree()
    tt.add(Task(id="t1", kind="DISCOVER", target="http://t", objective="crawl"))
    tt.transition("t1", "active")
    tt.transition("t1", "done")
    assert tt.revision == 3
    assert [x["status"] for x in tt.transitions] == ["ready", "active", "done"]
    assert tt.open_tasks() == []


def test_selection_prefers_web_tools():
    avail = {t: True for t in ["nuclei", "dalfox", "sqlmap", "wpscan", "nmap"]}
    fp = {"technologies": ["WordPress", "PHP"], "title": "blog"}
    tools = select_tools(fp, avail)
    assert tools[0] == "nuclei"
    assert "wpscan" in tools  # boosted by WordPress
    assert classify({"technologies": ["GraphQL"]}) == "api"
