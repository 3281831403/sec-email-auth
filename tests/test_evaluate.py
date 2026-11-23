"""mailauth 验收测试。

共 15 条，前 10 条分别覆盖题目列出的 10 个缺陷，后 5 条覆盖放行、拒绝、
子域错位、查找超限和批量一致性。当前 8 个桩全部抛 NotImplementedError，
因此 15 条全红；实现 src/mailauth/evaluate.py 后应全部转绿。
"""

import pytest

from mailauth.evaluate import (
    align_domain,
    auth_batch,
    evaluate_dmarc,
    evaluate_spf,
    lookup_guard,
    parse_record,
    qualifier_result,
    validate_policy,
)


def _unused_resolver(name, rrtype):
    raise AssertionError("本用例不应发起 DNS 查询: %s %s" % (name, rrtype))


def test_parse_record_normalizes_mechanism_case():
    """缺陷 1：机制名大小写混写必须仍被识别，不能因大小写比较而失效。"""
    record = parse_record("v=spf1 +IP4:192.0.2.9 -ALL")
    assert record["version"] == "spf1"
    assert [m["name"] for m in record["mechanisms"]] == ["ip4", "all"]
    assert record["mechanisms"][0]["value"] == "192.0.2.9"

    out = evaluate_spf(record, "192.0.2.9", "example.com", _unused_resolver)
    assert out["mechanism"] == "ip4"
    assert out["result"] == "pass"


def test_spf_evaluates_mechanisms_in_declared_order():
    """缺陷 2：必须按声明顺序求值，后面的 +all 不能覆盖前面的失败。"""
    record = parse_record("v=spf1 -ip4:192.0.2.9 +all")
    out = evaluate_spf(record, "192.0.2.9", "example.com", _unused_resolver)
    assert out["mechanism"] == "ip4"
    assert out["result"] == "fail"


def test_spf_stops_at_first_match():
    """缺陷 3：命中后必须停止，不得继续求值并取最后一条。"""
    calls = []

    def resolver(name, rrtype):
        calls.append((name, rrtype))
        return []

    record = parse_record("v=spf1 +ip4:192.0.2.9 include:later.example -all")
    out = evaluate_spf(record, "192.0.2.9", "example.com", resolver)
    assert out["mechanism"] == "ip4"
    assert out["result"] == "pass"
    assert out["lookups"] == 0
    assert calls == []


def test_strict_alignment_rejects_subdomain():
    """缺陷 4：严格对齐必须完全相等，不能用后缀比较把子域当作对齐。"""
    assert align_domain("mail.example.com", "example.com", True) == ""
    assert align_domain("example.com", "mail.example.com", True) == ""
    assert align_domain("Mail.Example.COM.", "mail.example.com", True) == "mail.example.com"


def test_relaxed_alignment_requires_same_org_domain():
    """缺陷 5：宽松对齐必须比较组织域，不同组织域的任意子域不算对齐。"""
    assert align_domain("mail.example.com", "example.com", False) == "mail.example.com"
    assert align_domain("example.com", "mail.example.com", False) == "example.com"
    assert align_domain("a.example.com", "b.example.net", False) == ""
    assert align_domain("example.com", "example.com.evil.test", False) == ""


def test_missing_qualifier_is_neutral():
    """缺陷 6：限定符缺失必须按中性处理，不能默认通过。"""
    record = parse_record("v=spf1 ip4:192.0.2.9 all")
    assert [m["qualifier"] for m in record["mechanisms"]] == ["?", "?"]

    out = evaluate_spf(record, "192.0.2.9", "example.com", _unused_resolver)
    assert out["mechanism"] == "ip4"
    assert out["result"] == "neutral"
    assert qualifier_result(None) == "neutral"
    assert qualifier_result("") == "neutral"


def test_lookup_guard_enforces_limit():
    """缺陷 7：查找次数必须有上限，边界处不得继续放大查询。"""
    assert lookup_guard(0, 10) is True
    assert lookup_guard(9, 10) is True
    assert lookup_guard(10, 10) is False
    assert lookup_guard(11, 10) is False

    with pytest.raises(ValueError):
        lookup_guard(-1, 10)


def test_policy_none_is_not_reject():
    """缺陷 8：策略为无时只能监控接收，不能按拒绝处理。"""
    subdomain_none = evaluate_dmarc(
        "v=DMARC1; p=reject; sp=none",
        False,
        {"p": "reject", "sp": "reject", "subdomain": True},
    )
    assert subdomain_none["action"] == "none"
    assert subdomain_none["policy"] == "none"

    fallback_none = evaluate_dmarc(None, False, {"p": "none", "sp": "none"})
    assert fallback_none["action"] == "none"
    assert fallback_none["reason"] == "policy_none"

    subdomain_quarantine = evaluate_dmarc(
        "v=DMARC1; p=reject; sp=quarantine",
        False,
        {"p": "reject", "sp": "reject", "subdomain": True},
    )
    assert subdomain_quarantine["action"] == "quarantine"


def test_validate_policy_checks_strict_alignment():
    """缺陷 9：策略校验必须检查 adkim 与 aspf 是否启用严格对齐。"""
    assert validate_policy(
        {"p": "reject", "sp": "reject", "adkim": "r", "aspf": "s", "lookup_limit": 10}
    ) == ["adkim_not_strict"]
    assert validate_policy(
        {"p": "reject", "sp": "reject", "adkim": "s", "aspf": "r", "lookup_limit": 10}
    ) == ["aspf_not_strict"]
    assert validate_policy(
        {"p": "reject", "sp": "reject", "adkim": "s", "aspf": "s", "lookup_limit": 10}
    ) == []
    assert validate_policy(
        {"p": "none", "sp": "none", "adkim": "s", "aspf": "r", "lookup_limit": None}
    ) == ["policy_none", "aspf_not_strict", "lookup_limit_missing"]


def test_batch_does_not_reuse_previous_message():
    """缺陷 10：批量评估不得复用解析结果，后一封不得命中前一封的域名。"""
    policy = {"p": "reject", "sp": "reject", "strict": False}
    messages = [
        {
            "from_domain": "example.com",
            "mail_from": "example.com",
            "ip": "192.0.2.1",
            "spf_record": "v=spf1 +all",
            "dmarc_record": "v=DMARC1; p=reject",
            "resolver": _unused_resolver,
        },
        {
            "from_domain": "mail.example.net",
            "mail_from": "example.net",
            "ip": "192.0.2.2",
            "spf_record": "v=spf1 -all",
            "dmarc_record": "v=DMARC1; p=reject",
            "resolver": _unused_resolver,
        },
    ]

    results = auth_batch(messages, policy)["results"]
    assert results[0]["from_domain"] == "example.com"
    assert results[0]["spf"] == "pass"
    assert results[0]["aligned"] is True
    assert results[0]["dmarc"] == "none"
    assert results[1]["from_domain"] == "mail.example.net"
    assert results[1]["spf"] == "fail"
    assert results[1]["aligned"] is False
    assert results[1]["dmarc"] == "reject"


def test_pass_mechanism_allows():
    """通过机制放行：+all 命中即 pass。"""
    out = evaluate_spf(
        parse_record("v=spf1 +all"), "203.0.113.9", "example.com", _unused_resolver
    )
    assert out["result"] == "pass"
    assert out["mechanism"] == "all"
    assert out["lookups"] == 0


def test_fail_mechanism_rejects():
    """失败机制拒绝：-all 命中即 fail。"""
    out = evaluate_spf(
        parse_record("v=spf1 -all"), "203.0.113.9", "example.com", _unused_resolver
    )
    assert out["result"] == "fail"
    assert out["mechanism"] == "all"


def test_subdomain_misalignment_is_detected():
    """子域不对齐被识别：严格模式下子域不对齐，DMARC 按拒绝处置。"""
    aligned = align_domain("mail.example.com", "example.com", True) != ""
    assert aligned is False

    out = evaluate_dmarc(
        "v=DMARC1; p=reject",
        aligned,
        {"p": "reject", "sp": "reject", "subdomain": True},
    )
    assert out["action"] == "reject"


def test_lookup_limit_returns_permerror():
    """查找超限返回错误：第 11 次查询前停止并返回 permerror。"""
    calls = []

    def resolver(name, rrtype):
        calls.append((name, rrtype))
        return []

    mechanisms = " ".join("+include:list%d.example" % index for index in range(11))
    record = parse_record("v=spf1 " + mechanisms + " -all")
    out = evaluate_spf(record, "203.0.113.9", "example.com", resolver)

    assert out["result"] == "permerror"
    assert out["lookups"] == 10
    assert len(calls) == 10
    assert out["reason"] == "lookup limit exceeded"


def test_batch_matches_individual_evaluation():
    """两批独立评估与单独评估相同：批量结果与逐条结果逐字段一致。"""
    policy = {"p": "reject", "sp": "reject", "strict": False}
    messages = [
        {
            "from_domain": "example.com",
            "mail_from": "example.com",
            "ip": "192.0.2.1",
            "spf_record": "v=spf1 +all",
            "dmarc_record": "v=DMARC1; p=reject",
            "resolver": _unused_resolver,
        },
        {
            "from_domain": "mail.example.net",
            "mail_from": "example.org",
            "ip": "192.0.2.2",
            "spf_record": "v=spf1 +all",
            "dmarc_record": "v=DMARC1; p=reject",
            "resolver": _unused_resolver,
        },
    ]

    first = auth_batch(messages, policy)["results"]
    second = auth_batch(messages, policy)["results"]
    individual = [
        auth_batch([message], policy)["results"][0] for message in messages
    ]

    assert first == second
    assert first == individual