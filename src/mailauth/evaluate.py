"""邮件发件认证评估核心。

本模块只依赖 Python 标准库（re、ipaddress、hashlib），不访问网络、不使用随机数。
所有 DNS 结果必须由调用方通过 resolver 参数注入，测试使用 pytest。

主要对象：
- SPF 策略记录：版本字段加若干机制，机制由限定符、名称和可选的冒号参数组成。
- DMARC 记录：分号分隔的键值对，用 p、sp 等标签描述处置策略。
- 对齐：From 域与 MAIL FROM 域相同（严格）或同组织域（宽松）。
"""

import ipaddress
import re

LOOKUP_LIMIT = 10

_QUALIFIERS = "+-~?"
_QUALIFIER_RESULTS = {
    "+": "pass",
    "-": "fail",
    "~": "softfail",
    "?": "neutral",
}
_IP_MECHANISMS = ("ip4", "ip6")
_DOMAIN_MECHANISMS = ("a", "mx", "include", "exists", "ptr")
_POLICY_VALUES = ("none", "quarantine", "reject")
_ALIGNMENT_VALUES = ("r", "s")


def _normalize_domain(value) -> str:
    """去首尾空白、转小写、去掉末尾一个点，并校验标签结构。"""
    if not isinstance(value, str):
        raise ValueError("domain must be a string")
    name = value.strip().lower()
    if name.endswith("."):
        name = name[:-1]
    labels = name.split(".")
    if len(labels) < 2 or any(label == "" for label in labels):
        raise ValueError("invalid domain: %r" % (value,))
    return name


def _normalize_policy_value(value) -> str:
    """把 DMARC 处置策略归一化并校验。"""
    if not isinstance(value, str):
        raise ValueError("invalid policy value: %r" % (value,))
    normalized = value.strip().lower()
    if normalized not in _POLICY_VALUES:
        raise ValueError("invalid policy value: %r" % (value,))
    return normalized


def _normalize_alignment_value(value) -> str:
    """把 DMARC 对齐模式归一化并校验。"""
    if not isinstance(value, str):
        raise ValueError("invalid alignment value: %r" % (value,))
    normalized = value.strip().lower()
    if normalized not in _ALIGNMENT_VALUES:
        raise ValueError("invalid alignment value: %r" % (value,))
    return normalized


def _empty_resolver(name, rrtype):
    """缺省解析器：任何名称都不存在。"""
    return []


def _permerror(mechanism, lookups) -> dict:
    return {
        "result": "permerror",
        "mechanism": mechanism,
        "lookups": lookups,
        "reason": "lookup limit exceeded",
    }


class _LookupLimitExceeded(Exception):
    """内部信号：本次评估的查找额度已经用尽。"""


def _ip_matches(value, cidr, address, version) -> bool:
    """判断地址是否落在机制 value/cidr 描述的网段内。"""
    if address is None or address.version != version:
        return False
    if not isinstance(value, str):
        return False
    text = value.strip()
    if not text:
        return False

    prefix = cidr
    if "/" in text:
        text, _, tail = text.rpartition("/")
        if prefix is None:
            try:
                prefix = int(tail)
            except ValueError:
                return False
    if prefix is None:
        prefix = 32 if version == 4 else 128
    if type(prefix) is not int:
        return False

    max_prefix = 32 if version == 4 else 128
    if prefix < 0 or prefix > max_prefix:
        return False
    try:
        network = ipaddress.ip_network("%s/%d" % (text, prefix), strict=False)
    except ValueError:
        return False
    return address in network


def parse_record(text) -> dict:
    """解析 SPF 策略记录文本。

    参数 text 是单条策略记录，例如 v=spf1 ip4:192.0.2.0/24 include:_spf.example.com -all
    返回 {"version": "spf1", "mechanisms": [...]}。

    返回结构：
    - version 固定为小写 spf1。首个空白分隔字段必须是 v=spf1，比较不区分大小写。
    - mechanisms 按文本中出现的顺序保存机制字典，每个机制字典恰好四个键：
      name、qualifier、value、cidr。
    - name 是机制名的小写形式。机制名解析不区分大小写，IP4、Include、ALL 与
      ip4、include、all 等价。支持的名称有 all、ip4、ip6、a、mx、include、
      exists、ptr；其他名称按小写保留，由求值函数按不匹配处理。
    - qualifier 是 +、-、~、? 之一。文本未写限定符时取 ?（中性），不得默认成
      +，未声明的机制不放行。
    - value 是机制中第一个冒号之后的内容。域名类机制（a、mx、include、exists、
      ptr）的 value 统一小写并去掉末尾一个点；ip4、ip6 的 value 保留原样以便
      解析地址；all 不带参数，value 为 None；没有冒号的机制 value 为 None。
    - cidr 是 ip4、ip6 机制末尾 /n 的整数前缀，范围分别是 0 到 32 与 0 到 128。
      没有斜杠前缀，或机制不是 ip4、ip6 时，cidr 为 None。

    约束：字段之间只按空白切分并忽略多余空白；机制参数只按第一个冒号切分，
    因此 IPv6 地址中的冒号保留在 value 内。不执行 DNS 查询，不引入随机性，
    所有大小写归一后的比较都是精确比较（容差 0）。

    以下情况抛 ValueError：文本为空、缺少 v=spf1 版本字段、版本字段出现在非
    首位、限定符非法、机制名为空、机制没有参数却写了冒号、all 带参数、冒号后
    内容为空、cidr 不是整数或越界。
    """
    if not isinstance(text, str):
        raise ValueError("record must be a string")

    fields = text.split()
    if not fields:
        raise ValueError("empty spf record")
    if fields[0].lower() != "v=spf1":
        raise ValueError("missing v=spf1 version field")

    mechanisms = []
    for term in fields[1:]:
        if term.lower() == "v=spf1":
            raise ValueError("v=spf1 must be the first field")

        index = 0
        qualifier = "?"
        if term[0] in _QUALIFIERS:
            qualifier = term[0]
            index = 1
        body = term[index:]
        if not body:
            raise ValueError("empty mechanism name")

        if ":" in body:
            name_text, value = body.split(":", 1)
            has_value = True
        else:
            name_text, value = body, None
            has_value = False

        name = name_text.lower()
        if not name:
            raise ValueError("empty mechanism name")
        if name == "all" and has_value:
            raise ValueError("all mechanism takes no argument")
        if has_value and value == "":
            raise ValueError("empty mechanism argument")

        cidr = None
        if name in _IP_MECHANISMS:
            if value is not None and "/" in value:
                value, _, prefix_text = value.rpartition("/")
                try:
                    cidr = int(prefix_text)
                except ValueError:
                    raise ValueError("cidr is not an integer: %r" % (prefix_text,))
                maximum = 32 if name == "ip4" else 128
                if cidr < 0 or cidr > maximum:
                    raise ValueError("cidr out of range: %d" % (cidr,))
                if value == "":
                    raise ValueError("empty mechanism argument")
        elif name in _DOMAIN_MECHANISMS and value is not None:
            value = value.lower()
            if value.endswith("."):
                value = value[:-1]

        mechanisms.append(
            {
                "name": name,
                "qualifier": qualifier,
                "value": value,
                "cidr": cidr,
            }
        )

    return {"version": "spf1", "mechanisms": mechanisms}


def align_domain(from_domain, mail_from, strict) -> str:
    """判定 From 域与 MAIL FROM 域是否对齐，并返回对齐后的域名。

    参数：
    - from_domain：邮件头 From 中的域名。
    - mail_from：SPF 检查使用的 MAIL FROM 域名。
    - strict：True 为严格对齐，False 为宽松对齐。

    归一化：去掉首尾空白、转小写、去掉末尾一个点。归一化后必须至少有两个
    标签且没有空标签，否则抛 ValueError。

    对齐结果只有两种（容差 0，不做前缀、后缀、子串或编辑距离容忍）：
    - 对齐时返回 from_domain 的归一化域名。
    - 不对齐时返回空字符串。

    严格对齐：两个归一化域名必须逐字符完全相等，因此 mail.example.com 与
    example.com 不对齐，example.com 与 mail.example.com 也不对齐。

    宽松对齐：两个域名的组织域必须相同。组织域取最后两个标签（本模块不带
    公共后缀表）：a.b.example.com 与 example.com 的组织域都是 example.com，
    因此宽松对齐；example.com 与 example.com.evil.test 的组织域分别是
    example.com 与 evil.test，因此不对齐。禁止用字符串后缀或包含关系判断
    对齐，任何不同组织域的域名都不对齐。

    判定对称：交换 from_domain 与 mail_from 不会改变是否对齐；返回值始终是
    from_domain 一侧的归一化域名。函数不访问网络、不使用随机数。
    """
    left = _normalize_domain(from_domain)
    right = _normalize_domain(mail_from)

    if strict:
        aligned = left == right
    else:
        left_labels = left.split(".")
        right_labels = right.split(".")
        if len(left_labels) < 2 or len(right_labels) < 2:
            aligned = False
        else:
            aligned = left_labels[-2:] == right_labels[-2:]

    return left if aligned else ""


def qualifier_result(qualifier) -> str:
    """把 SPF 限定符映射为认证结果字符串。

    映射规则（只认单个字符，比较前转字符串并去首尾空白，容差 0）：
    + 映射为 pass；
    - 映射为 fail；
    ~ 映射为 softfail；
    ? 映射为 neutral。

    限定符缺失（None、空字符串或只含空白）时返回 neutral，不得默认成 pass，
    也不得默认放行。其他取值抛 ValueError。

    返回值只可能是 pass、fail、softfail、neutral 之一。函数无副作用，
    不访问网络，不使用随机数。
    """
    if qualifier is None:
        return "neutral"
    text = str(qualifier).strip()
    if not text:
        return "neutral"
    if text in _QUALIFIER_RESULTS:
        return _QUALIFIER_RESULTS[text]
    raise ValueError("invalid qualifier: %r" % (qualifier,))


def evaluate_spf(record, ip, sender, resolver) -> dict:
    """按声明顺序逐机制求值 SPF，命中即停。

    参数：
    - record：parse_record 返回的字典，必须含 mechanisms 列表。
    - ip：待检查的 IPv4 或 IPv6 地址字符串。
    - sender：MAIL FROM 域名，供 a、mx、exists、ptr 机制使用；使用前转小写
      并去掉末尾一个点。
    - resolver：调用方注入的 DNS 查询函数，签名 resolver(name, rrtype) 返回
      list[str]；返回空列表表示记录不存在。禁止在模块内访问真实网络。

    求值规则：
    - mechanisms 必须按声明顺序求值，不得排序或重排。第一条匹配的机制立即
      决定结果，后面的机制即使限定符更宽松也不能覆盖前面的结果。
    - 命中后立刻停止：后续机制不再匹配，也不再产生任何 resolver 调用。
    - 机制匹配（地址与名称比较的容差均为 0）：
      all      匹配任何地址，不查询。
      ip4      ip 是 IPv4 且落在 value 的 CIDR 内；无斜杠按 /32 处理。
      ip6      ip 是 IPv6 且落在 value 的 CIDR 内；无斜杠按 /128 处理。
      include  resolver(value, TXT) 返回的任一条目以 v=spf1 开头（大小写
               不敏感）即匹配。只查询这一层，不递归求值。
      a        resolver(value 或 sender, A) 返回非空即匹配。
      mx       resolver(value 或 sender, MX) 返回非空即匹配。
      exists   resolver(value 或 sender, A) 返回非空即匹配。
      ptr      resolver(value 或 sender, PTR) 返回非空即匹配。
      其他机制名一律不匹配，也不发起查询。
    - 命中结果由命中机制的 qualifier 经 qualifier_result 映射得到。没有任何
      机制命中时 result 为 neutral、mechanism 为 None，不得默认通过。

    查找上限：单次调用最多发起 10 次 resolver 查询（LOOKUP_LIMIT），整个记录
    共享这一个额度，不按机制重置。每次查询前调用 lookup_guard(已用次数, 10)。
    额度用尽后仍需要查询时立即停止并返回 permerror，不得再调用 resolver；
    此时 reason 固定为 lookup limit exceeded，lookups 等于 10。

    返回值：正常情况下字典恰好三个键。
    - result：pass、fail、softfail、neutral 或 permerror。
    - mechanism：命中的机制名（小写）；没有命中时为 None；查找超限时为触发
      查询的机制名。
    - lookups：本次实际调用 resolver 的次数，正常路径不超过 10。
    permerror 时额外包含 reason 键。

    同一输入与同一 resolver 多次调用结果必须一致。每次调用独立计数，不缓存、
    不递归、不共享状态、不使用随机数。
    """
    mechanisms = record["mechanisms"]

    if not isinstance(sender, str):
        raise ValueError("sender must be a string")
    sender = sender.strip().lower()
    if sender.endswith("."):
        sender = sender[:-1]

    try:
        address = ipaddress.ip_address(ip.strip())
    except (AttributeError, ValueError):
        address = None

    lookups = 0

    def lookup(name, rrtype):
        """带额度检查的解析查询；额度用尽时抛出内部信号。"""
        nonlocal lookups
        if not lookup_guard(lookups, LOOKUP_LIMIT):
            raise _LookupLimitExceeded
        result = resolver(name, rrtype)
        lookups += 1
        return result if result is not None else []

    def matches(mechanism):
        name = mechanism["name"]
        value = mechanism["value"]

        if name == "all":
            return True
        if name == "ip4":
            return _ip_matches(value, mechanism["cidr"], address, 4)
        if name == "ip6":
            return _ip_matches(value, mechanism["cidr"], address, 6)
        if name == "include":
            if value is None:
                return False
            entries = lookup(value, "TXT")
            return any(
                isinstance(entry, str)
                and entry.strip().lower().startswith("v=spf1")
                for entry in entries
            )
        if name in ("a", "mx", "exists", "ptr"):
            target = value if value is not None else sender
            rrtype = {"a": "A", "mx": "MX", "exists": "A", "ptr": "PTR"}[name]
            return len(lookup(target, rrtype)) > 0
        return False

    for mechanism in mechanisms:
        try:
            hit = matches(mechanism)
        except _LookupLimitExceeded:
            return _permerror(mechanism["name"], lookups)
        if hit:
            return {
                "result": qualifier_result(mechanism["qualifier"]),
                "mechanism": mechanism["name"],
                "lookups": lookups,
            }

    return {"result": "neutral", "mechanism": None, "lookups": lookups}


def evaluate_dmarc(record, aligned, policy) -> dict:
    """根据对齐结果和 DMARC 策略给出处置。

    参数：
    - record：DMARC 记录文本，可为 None 或空字符串（表示没有记录）。非空记录
      按分号分割成键值对，键和值去掉空白并转小写，必须有 v=DMARC1（不区分
      大小写），重复标签与缺少等号的片段都抛 ValueError。
    - aligned：布尔值，表示 SPF 或 DKIM 是否对齐。
    - policy：兜底策略字典。p 必填；sp 可选，缺省等于 p；subdomain 可选，
      缺省为 False，表示当前 From 域是否为组织域的子域。p、sp 的取值必须是
      none、quarantine、reject 之一，比较时大小写归一并且精确匹配（容差 0），
      未知取值抛 ValueError。

    生效策略的优先级：
    1. subdomain 为 True 且记录有 sp 标签时使用 sp；
    2. 否则记录有 p 标签时使用 p；
    3. 否则 subdomain 为 True 时使用 policy 的 sp，否则使用 policy 的 p。

    处置规则：
    - aligned 为 True 时 action 为 none（接收），reason 为 aligned。
    - aligned 为 False 时 action 等于生效策略，reason 为 policy_ 加生效策略。
      策略 none 只表示监控并接收，绝对不能转成 reject，正常邮件不得被误拒。
    - action 只可能是 none、quarantine、reject。

    返回字典恰好四个键：action、aligned、policy、reason，其中 policy 是生效
    策略。函数不访问网络、不修改入参、不使用随机数，策略字符串不做模糊匹配。
    """
    if not isinstance(policy, dict):
        raise ValueError("policy must be a dict")
    if "p" not in policy:
        raise ValueError("policy.p is required")

    record_tags = {}
    text = None if record is None else record
    if text is not None and not isinstance(text, str):
        raise ValueError("dmarc record must be a string")

    if text is not None and text.strip():
        for segment in text.split(";"):
            segment = segment.strip()
            if not segment:
                continue
            if "=" not in segment:
                raise ValueError("malformed dmarc tag: %r" % (segment,))
            key, _, value = segment.partition("=")
            key = key.strip().lower()
            value = value.strip().lower()
            if not key:
                raise ValueError("malformed dmarc tag: %r" % (segment,))
            if key in record_tags:
                raise ValueError("duplicate dmarc tag: %r" % (key,))
            record_tags[key] = value

        if "v" not in record_tags:
            raise ValueError("missing v=DMARC1")
        if record_tags["v"] != "dmarc1":
            raise ValueError("invalid dmarc version: %r" % (record_tags["v"],))

    fallback_p = _normalize_policy_value(policy["p"])
    fallback_sp = policy.get("sp", fallback_p)
    fallback_sp = _normalize_policy_value(fallback_sp)
    subdomain = bool(policy.get("subdomain", False))

    record_p = None
    if "p" in record_tags:
        record_p = _normalize_policy_value(record_tags["p"])
    record_sp = None
    if "sp" in record_tags:
        record_sp = _normalize_policy_value(record_tags["sp"])

    if subdomain and record_sp is not None:
        effective = record_sp
    elif record_p is not None:
        effective = record_p
    elif subdomain:
        effective = fallback_sp
    else:
        effective = fallback_p

    if aligned:
        action = "none"
        reason = "aligned"
    else:
        action = effective
        reason = "policy_" + effective

    return {
        "action": action,
        "aligned": bool(aligned),
        "policy": effective,
        "reason": reason,
    }


def lookup_guard(count, limit) -> bool:
    """判断是否还可以发起新的解析查询。

    count 是本次评估已经发起的查询次数，limit 是允许的总查询上限。count 小于
    limit 时返回 True；count 等于或大于 limit 时返回 False。上限本身包含在
    额度内，边界判断的容差为 0。

    count 为负数、limit 不是正整数、或参数不是整数时抛 ValueError。该函数
    只做计数判定，不发起查询、不访问网络、不使用随机数。
    """
    if isinstance(count, bool) or not isinstance(count, int):
        raise ValueError("count must be an integer")
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise ValueError("limit must be an integer")
    if count < 0:
        raise ValueError("count must not be negative")
    if limit <= 0:
        raise ValueError("limit must be a positive integer")
    return count < limit


def validate_policy(policy) -> list[str]:
    """检查 DMARC 与查找上限配置，按固定顺序返回问题代码列表。

    policy 是字典，可含 p、sp、adkim、aspf、lookup_limit。p 缺失视为 none；
    p、sp 出现时必须为 none、quarantine、reject 之一；adkim、aspf 出现时必须
    为 r 或 s（大小写归一后精确比较，容差 0）。取值非法或 policy 不是字典时
    抛 ValueError。

    返回的问题代码按以下固定顺序排列，空列表表示没有发现问题：
    - policy_none：p 缺失或为 none，策略过宽，无法拒收。
    - adkim_not_strict：adkim 不是 s，DKIM 未启用严格对齐。
    - aspf_not_strict：aspf 不是 s，SPF 未启用严格对齐。
    - lookup_limit_missing：lookup_limit 缺失、不是整数、小于 1 或大于 10，
      即没有有效的查找上限。

    检查严格对齐是本函数的核心职责，adkim 与 aspf 必须分别校验，不能只看
    其中一个，也不能完全不看。函数不修改入参、不访问网络、不使用随机数。
    """
    if not isinstance(policy, dict):
        raise ValueError("policy must be a dict")

    p_value = policy.get("p", "none")
    p_value = _normalize_policy_value(p_value)
    if "sp" in policy:
        _normalize_policy_value(policy["sp"])

    adkim = "r"
    if "adkim" in policy:
        adkim = _normalize_alignment_value(policy["adkim"])
    aspf = "r"
    if "aspf" in policy:
        aspf = _normalize_alignment_value(policy["aspf"])

    problems = []
    if p_value == "none":
        problems.append("policy_none")
    if adkim != "s":
        problems.append("adkim_not_strict")
    if aspf != "s":
        problems.append("aspf_not_strict")

    limit = policy.get("lookup_limit")
    if (
        isinstance(limit, bool)
        or not isinstance(limit, int)
        or limit < 1
        or limit > 10
    ):
        problems.append("lookup_limit_missing")

    return problems


def auth_batch(messages, policy) -> dict:
    """批量评估邮件，每条消息完全独立。

    messages 是消息字典的列表。每条消息包含：
    - from_domain：From 头域名。
    - mail_from：MAIL FROM 域名。
    - ip：连接来源 IP 字符串。
    - spf_record：SPF 策略记录文本。
    - dmarc_record：DMARC 记录文本，可为 None。
    - resolver：可选的 DNS 查询函数 resolver(name, rrtype) 返回 list[str]；
      缺省时使用总是返回空列表的解析器。每条消息只使用自己的 resolver。
    缺少必需字段时抛 ValueError。

    policy 是兜底策略字典：p 缺省为 none；sp 缺省等于 p；strict 缺省为 False，
    True 表示严格对齐，False 表示宽松对齐。

    每条消息独立完成：parse_record 解析自己的 SPF 文本；evaluate_spf 使用自己的
    ip、mail_from 与 resolver；align_domain 使用自己的 from_domain 与 mail_from
    判定对齐；evaluate_dmarc 使用自己的 dmarc_record 与 policy。禁止跨消息缓存
    解析结果、复用查找计数或沿用上一封邮件的域名，上一封邮件的结果不得影响
    下一封邮件。

    对齐条件：SPF 结果必须是 pass，且 align_domain 返回非空。subdomain 由
    from_domain 归一化后的标签数是否大于 2 决定。

    返回 {"results": [...]}，每条结果字典恰好四个键：
    - from_domain：归一化小写并去掉末尾点的 From 域；
    - spf：SPF 结果字符串；
    - dmarc：DMARC 处置字符串；
    - aligned：布尔值。

    无模块级状态、无缓存、无随机数。容差 0：同一批消息拆成多批或逐条调用，
    结果必须逐字段完全相等；消息顺序不影响单条结果；输入字典不得被修改。
    """
    if not isinstance(policy, dict):
        raise ValueError("policy must be a dict")
    if not isinstance(messages, (list, tuple)):
        raise ValueError("messages must be a list")

    results = []
    for message in messages:
        if not isinstance(message, dict):
            raise ValueError("message must be a dict")
        for field in ("from_domain", "mail_from", "ip", "spf_record"):
            if field not in message:
                raise ValueError("missing message field: %s" % (field,))

        from_domain = message["from_domain"]
        mail_from = message["mail_from"]
        if not isinstance(from_domain, str) or not isinstance(mail_from, str):
            raise ValueError("domain fields must be strings")

        normalized_from = _normalize_domain(from_domain)
        normalized_mail = _normalize_domain(mail_from)

        resolver = message.get("resolver", _empty_resolver)
        if resolver is None:
            resolver = _empty_resolver

        record = parse_record(message["spf_record"])
        spf = evaluate_spf(record, message["ip"], normalized_mail, resolver)
        spf_result = spf["result"]

        strict = bool(policy.get("strict", False))
        aligned_domain = align_domain(normalized_from, normalized_mail, strict)
        aligned = spf_result == "pass" and aligned_domain != ""

        dmarc_message_policy = {
            "p": policy.get("p", "none"),
            "subdomain": normalized_from.count(".") + 1 > 2,
        }
        if "sp" in policy:
            dmarc_message_policy["sp"] = policy["sp"]

        dmarc = evaluate_dmarc(
            message.get("dmarc_record"), aligned, dmarc_message_policy
        )

        results.append(
            {
                "from_domain": normalized_from,
                "spf": spf_result,
                "dmarc": dmarc["action"],
                "aligned": aligned,
            }
        )

    return {"results": results}