from taintwall.eval import make_report


def test_r1_table_renders_from_committed_results() -> None:
    out = make_report.r1_table()
    assert "325/335" in out
    assert "44/335" in out
    assert "p<0.001" in out


def test_vs_none_identity() -> None:
    o = {("a",): True}
    assert make_report._vs_none(o, o, "none") == "—"
