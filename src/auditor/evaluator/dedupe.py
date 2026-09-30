def dedupe_findings(findings: list) -> list:
    """Groups findings by file, category, and approximate line number to remove duplicates."""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    conf_rank = {"high": 0, "medium": 1, "low": 2}
    best = {}
    
    for f_ in findings:
        line_val = f_.get("line")
        approx_line = line_val // 10 if isinstance(line_val, int) else 0
        key = (f_.get("file"), f_.get("category"), approx_line)
        
        cur = best.get(key)
        if cur is None or conf_rank.get(f_.get("confidence"), 9) < conf_rank.get(cur.get("confidence"), 9):
            best[key] = f_
            
    out = list(best.values())
    out.sort(key=lambda f_: order.get(f_.get("severity"), 9))
    return out
