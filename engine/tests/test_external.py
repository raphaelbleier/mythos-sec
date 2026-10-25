"""Parser tests for external-tool output (no binaries required)."""

from mythos.external import parse_dalfox_jsonl


DALFOX_SAMPLE = (
    '{"meta":{"dalfox_version":"3.2.3","findings_count":1}}\n'
    '{"confidence":"high","cwe":"CWE-79",'
    '"data":"http://t/search?q=%3Csvg%20onload%3Dalert%281%29%3E",'
    '"evidence":"DOM verification successful for param q",'
    '"inject_type":"inHTML","param":"q",'
    '"payload":"<svg onload=alert(1)>","severity":"High","type":"V"}\n'
)


def test_parse_dalfox_jsonl_skips_meta_and_parses_finding():
    findings = parse_dalfox_jsonl(DALFOX_SAMPLE, "http://t/search?q=test")
    assert len(findings) == 1
    f = findings[0]
    assert f.kind == "reflected-xss"
    assert f.severity.value == "high"
    assert f.param == "q"
    assert f.confidence == "certain"       # type == "V"
    assert f.source == "dalfox"
    assert "CWE-79" in f.references


def test_parse_dalfox_jsonl_empty():
    assert parse_dalfox_jsonl("", "http://t") == []
    assert parse_dalfox_jsonl('{"meta":{"findings_count":0}}', "http://t") == []
