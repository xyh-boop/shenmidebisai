# ruff: noqa: E501, RUF001
"""Canonical JSON and self-contained HTML reporting for AegisFlow."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from jinja2 import Environment, StrictUndefined

from aegisflow.contracts import ReportEnvelope, Severity

_SEVERITY_ORDER = tuple(severity.value for severity in Severity)

_SEVERITY_LABELS = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "提示",
}
_DISPOSITION_LABELS = {
    "confirmed": "已确认",
    "likely": "疑似",
    "rejected": "已排除",
    "needs_review": "待人工复核",
}
_NODE_KIND_LABELS = {
    "source": "输入源",
    "propagation": "传播节点",
    "sanitizer": "净化处理",
    "constraint": "约束条件",
    "sink": "危险汇点",
    "context": "上下文",
}
_RELATION_LABELS = {
    "flows_to": "流向",
    "sanitized_by": "经由净化",
    "guarded_by": "受约束于",
    "derived_from": "派生自",
}
_AGENT_ROLE_LABELS = {
    "scout": "发现 Agent",
    "tracer": "追踪 Agent",
    "verifier": "验证 Agent",
    "critic": "质疑 Agent",
    "arbiter": "裁决 Agent",
}
_VERDICT_LABELS = {
    "confirm": "确认",
    "reject": "排除",
    "needs_review": "待复核",
}
_RUN_MODE_LABELS = {"offline": "离线模式", "agent": "Agent 模式"}
_DIAGNOSTIC_LEVEL_LABELS = {"error": "错误", "warning": "警告", "info": "提示"}

_HTML_TEMPLATE = r"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="dark">
  <title>AegisFlow 安全审计报告</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #111315;
      --surface: #181b1e;
      --surface-2: #202428;
      --line: #343a40;
      --text: #f1f3f4;
      --muted: #a9b0b7;
      --red: #f06a6a;
      --amber: #e3b45d;
      --green: #66c792;
      --cyan: #5ab8c9;
      --radius: 6px;
      --mono: "Cascadia Mono", "SFMono-Regular", Consolas, monospace;
      --sans: "Segoe UI Variable", "Segoe UI", system-ui, sans-serif;
    }
    * { box-sizing: border-box; }
    html { background: var(--bg); scroll-behavior: smooth; }
    html, body { max-width: 100%; overflow-x: hidden; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: var(--sans);
      font-size: 15px;
      line-height: 1.55;
    }
    a { color: var(--cyan); }
    .skip-link {
      position: absolute;
      top: -4rem;
      left: 1rem;
      z-index: 2;
      padding: .6rem .8rem;
      border-radius: var(--radius);
      background: var(--text);
      color: var(--bg);
    }
    .skip-link:focus { top: 1rem; }
    .shell { min-width: 0; width: min(1180px, calc(100% - 40px)); max-width: 100%; margin: 0 auto; }
    header { border-bottom: 1px solid var(--line); padding: 42px 0 30px; }
    .brand-row, .finding-head, .section-head, .node-head, .decision-head {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 20px;
    }
    .brand { margin: 0; font-size: clamp(1.8rem, 5vw, 3.4rem); line-height: 1; letter-spacing: 0; }
    .subtitle { max-width: 68ch; margin: 14px 0 0; color: var(--muted); overflow-wrap: anywhere; word-break: break-word; }
    .run-mode, .tag {
      display: inline-flex;
      align-items: center;
      min-height: 28px;
      padding: 4px 9px;
      border: 1px solid var(--line);
      border-radius: var(--radius);
      background: var(--surface);
      color: var(--text);
      font: 700 .72rem/1 var(--mono);
      text-transform: uppercase;
    }
    .run-grid, .metric-grid, .severity-grid {
      display: grid;
      min-width: 0;
      max-width: 100%;
      gap: 1px;
      overflow: hidden;
      margin-top: 26px;
      border: 1px solid var(--line);
      border-radius: var(--radius);
      background: var(--line);
    }
    .run-grid { grid-template-columns: repeat(4, minmax(0, 1fr)); }
    .metric-grid { grid-template-columns: repeat(4, minmax(0, 1fr)); }
    .severity-grid { grid-template-columns: repeat(5, minmax(0, 1fr)); }
    .datum { min-width: 0; padding: 16px; background: var(--surface); }
    .datum dt { margin: 0 0 7px; color: var(--muted); font-size: .75rem; }
    .datum dd { margin: 0; font: 650 1.15rem/1.25 var(--mono); overflow-wrap: anywhere; word-break: break-word; }
    main { padding: 34px 0 68px; }
    section + section { margin-top: 42px; }
    h2 { margin: 0; font-size: 1.25rem; letter-spacing: 0; }
    h3 { margin: 0; font-size: 1.05rem; letter-spacing: 0; }
    h4 { margin: 0; font-size: .9rem; letter-spacing: 0; }
    .section-note { margin: 3px 0 0; color: var(--muted); }
    .critical { color: var(--red); }
    .high { color: #f28b6d; }
    .medium { color: var(--amber); }
    .low { color: var(--cyan); }
    .info { color: var(--muted); }
    .good { color: var(--green); }
    .finding {
      margin-top: 18px;
      overflow: hidden;
      border: 1px solid var(--line);
      border-left: 4px solid var(--line);
      border-radius: var(--radius);
      background: var(--surface);
    }
    .finding.severity-critical, .finding.severity-high { border-left-color: var(--red); }
    .finding.severity-medium { border-left-color: var(--amber); }
    .finding.severity-low { border-left-color: var(--cyan); }
    .finding.severity-info { border-left-color: var(--muted); }
    .finding-head { padding: 20px; border-bottom: 1px solid var(--line); }
    .finding-title { min-width: 0; }
    .finding-title p { margin: 7px 0 0; color: var(--muted); font: .78rem/1.5 var(--mono); overflow-wrap: anywhere; }
    .tags { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 7px; }
    .finding-body { padding: 0 20px 22px; }
    .finding-block { padding-top: 22px; }
    .finding-block + .finding-block { margin-top: 22px; border-top: 1px solid var(--line); }
    .node-grid, .review-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
      margin-top: 12px;
    }
    .node, .review-column {
      min-width: 0;
      padding: 14px;
      border: 1px solid var(--line);
      border-radius: var(--radius);
      background: var(--surface-2);
    }
    .node-kind { color: var(--cyan); font: 700 .72rem/1 var(--mono); text-transform: uppercase; }
    .node-location { color: var(--muted); font: .75rem/1.4 var(--mono); overflow-wrap: anywhere; }
    .node p { margin: 10px 0 0; }
    pre {
      margin: 10px 0 0;
      padding: 11px;
      overflow-x: auto;
      border-radius: var(--radius);
      background: #121416;
      color: #dfe4e8;
      font: .78rem/1.55 var(--mono);
      white-space: pre-wrap;
      overflow-wrap: anywhere;
    }
    .edge-list, .decision-list, .diagnostic-list { display: grid; gap: 8px; margin: 12px 0 0; padding: 0; list-style: none; }
    .edge-list li, .decision, .diagnostic {
      padding: 12px 14px;
      border-left: 2px solid var(--cyan);
      background: var(--surface-2);
      overflow-wrap: anywhere;
    }
    .edge-list code { font-family: var(--mono); color: var(--text); }
    .decision { border-left-color: var(--line); }
    .decision.verdict-confirm { border-left-color: var(--green); }
    .decision.verdict-reject { border-left-color: var(--red); }
    .decision.verdict-needs_review { border-left-color: var(--amber); }
    .decision p, .diagnostic p { margin: 7px 0 0; color: var(--muted); }
    .decision-meta { color: var(--muted); font: .74rem/1.45 var(--mono); overflow-wrap: anywhere; word-break: break-word; }
    .review-column.support { border-top: 3px solid var(--green); }
    .review-column.counter { border-top: 3px solid var(--amber); }
    .review-column ul { margin: 10px 0 0; padding-left: 18px; }
    .remediation { margin: 12px 0 0; padding: 14px; border-left: 3px solid var(--green); background: var(--surface-2); white-space: pre-wrap; overflow-wrap: anywhere; }
    .diagnostic.level-error { border-left-color: var(--red); }
    .diagnostic.level-warning { border-left-color: var(--amber); }
    .diagnostic.level-info { border-left-color: var(--cyan); }
    .empty { margin-top: 14px; padding: 22px; border: 1px dashed var(--line); border-radius: var(--radius); color: var(--muted); }
    footer { padding: 22px 0 38px; border-top: 1px solid var(--line); color: var(--muted); font-size: .8rem; }
    code, .mono { font-family: var(--mono); }
    @media (max-width: 760px) {
      .shell { width: min(100% - 28px, 1180px); }
      header { padding-top: 28px; }
      .brand-row, .finding-head, .section-head { display: block; }
      .run-mode { margin-top: 16px; }
      .run-grid { grid-template-columns: minmax(0, 1fr); }
      .metric-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .severity-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); overflow-x: hidden; }
      .tags { justify-content: flex-start; margin-top: 14px; }
      .node-grid, .review-grid { grid-template-columns: minmax(0, 1fr); }
      .finding-head, .finding-body { padding-left: 14px; padding-right: 14px; }
    }
    @media (max-width: 430px) {
      .run-grid, .metric-grid { grid-template-columns: minmax(0, 1fr); }
      .brand { font-size: 2rem; }
      .datum { padding: 13px; }
    }
    @media print {
      :root { color-scheme: light; --bg: #f7f7f5; --surface: #ffffff; --surface-2: #eeeeeb; --line: #b8b8b2; --text: #17191b; --muted: #555b61; }
      body { font-size: 11pt; }
      .shell { width: 100%; }
      .finding { break-inside: avoid; }
    }
  </style>
</head>
<body>
  <a class="skip-link" href="#report-main">跳转至报告正文</a>
  <header>
    <div class="shell">
      <div class="brand-row">
        <div>
          <h1 class="brand">AegisFlow 安全审计</h1>
          <p class="subtitle">面向 <span class="mono">{{ report.run.root }}</span> 的证据驱动安全发现、路由决策与扫描成本分析。</p>
        </div>
        <span class="run-mode">{{ run_mode_labels[report.run.mode] }}</span>
      </div>
      <dl class="run-grid">
        <div class="datum"><dt>运行 ID</dt><dd>{{ report.run.run_id }}</dd></div>
        <div class="datum"><dt>开始时间</dt><dd>{{ report.run.started_at }}</dd></div>
        <div class="datum"><dt>完成时间</dt><dd>{{ report.run.completed_at }}</dd></div>
        <div class="datum"><dt>配置摘要</dt><dd title="{{ report.run.configuration_digest }}">{{ report.run.configuration_digest[:12] }}</dd></div>
      </dl>
    </div>
  </header>
  <main id="report-main" class="shell">
    <section aria-labelledby="severity-heading">
      <div class="section-head">
        <div><h2 id="severity-heading">安全态势</h2><p class="section-note">按严重等级汇总的最终发现。</p></div>
      </div>
      <dl class="severity-grid">
      {% for severity in severity_order %}
        <div class="datum"><dt class="{{ severity }}">{{ severity_labels[severity] }}</dt><dd>{{ severity_counts[severity] }}</dd></div>
      {% endfor %}
      </dl>
    </section>

    <section aria-labelledby="metrics-heading">
      <h2 id="metrics-heading">运行指标</h2>
      <dl class="metric-grid">
        <div class="datum"><dt>已扫描文件</dt><dd>{{ report.metrics.files_scanned }}</dd></div>
        <div class="datum"><dt>已扫描代码行</dt><dd>{{ report.metrics.lines_scanned }}</dd></div>
        <div class="datum"><dt>总耗时</dt><dd>{{ report.metrics.elapsed_ms }} 毫秒</dd></div>
        <div class="datum"><dt>首个高危发现</dt><dd>{% if report.metrics.time_to_first_high_ms is not none %}{{ report.metrics.time_to_first_high_ms }} 毫秒{% else %}未发现{% endif %}</dd></div>
        <div class="datum"><dt>候选项</dt><dd>{{ report.metrics.candidates_total }}</dd></div>
        <div class="datum"><dt>已确认</dt><dd class="good">{{ report.metrics.findings_confirmed }}</dd></div>
        <div class="datum"><dt>已排除</dt><dd>{{ report.metrics.findings_rejected }}</dd></div>
        <div class="datum"><dt>待人工复核</dt><dd>{{ report.metrics.human_review_required }}</dd></div>
        <div class="datum"><dt>模型请求次数</dt><dd>{{ report.metrics.model_requests }}</dd></div>
        <div class="datum"><dt>输入 Token</dt><dd>{{ report.metrics.prompt_tokens }}</dd></div>
        <div class="datum"><dt>输出 Token</dt><dd>{{ report.metrics.completion_tokens }}</dd></div>
        <div class="datum"><dt>预估成本</dt><dd>{{ "%.6f"|format(report.metrics.estimated_cost_usd) }} 美元</dd></div>
      </dl>
    </section>

    <section aria-labelledby="findings-heading">
      <div class="section-head">
        <div><h2 id="findings-heading">漏洞发现</h2><p class="section-note">每个候选项的验证证据与决策记录。</p></div>
      </div>
      {% if report.findings %}
      {% for finding in report.findings %}
      <article class="finding severity-{{ finding.severity }}" id="finding-{{ finding.finding_id }}">
        <div class="finding-head">
          <div class="finding-title">
            <h3>{{ finding.title }}</h3>
            <p>{{ finding.path }}:{{ finding.start_line }}{% if finding.end_line != finding.start_line %}-{{ finding.end_line }}{% endif %} | {{ finding.rule_id }} | {{ finding.cwe }}</p>
          </div>
          <div class="tags" aria-label="发现状态">
            <span class="tag {{ finding.severity }}">{{ severity_labels[finding.severity] }}</span>
            <span class="tag">{{ disposition_labels[finding.disposition] }}</span>
            <span class="tag">置信度 {{ "%.0f"|format(finding.confidence * 100) }}%</span>
          </div>
        </div>
        <div class="finding-body">
          <div class="finding-block">
            <h4>证据图</h4>
            <div class="node-grid">
            {% for node in finding.nodes %}
              <div class="node" id="node-{{ finding.finding_id }}-{{ node.node_id }}">
                <div class="node-head"><span class="node-kind">{{ node_kind_labels[node.kind] }}</span><span class="node-location">{{ node.path }}:{{ node.line }}</span></div>
                <p>{{ node.description }}{% if node.symbol %} <span class="mono">{{ node.symbol }}</span>{% endif %}</p>
                <pre>{{ node.snippet }}</pre>
              </div>
            {% endfor %}
            </div>
            {% if finding.edges %}
            <ol class="edge-list" aria-label="证据关系">
            {% for edge in finding.edges %}
              <li><code>{{ edge.source_id }}</code> <span class="mono">{{ relation_labels[edge.relation] }}</span> <code>{{ edge.target_id }}</code></li>
            {% endfor %}
            </ol>
            {% endif %}
          </div>

          <div class="finding-block">
            <h4>路由与决策时间线</h4>
            {% if finding.decisions %}
            <ol class="decision-list">
            {% for decision in finding.decisions %}
              <li class="decision verdict-{{ decision.verdict }}">
                <div class="decision-head"><strong>{{ agent_role_labels[decision.agent] }}</strong><span class="decision-meta">{{ verdict_labels[decision.verdict] }} | {{ "%.0f"|format(decision.confidence * 100) }}% | {{ decision.latency_ms }} 毫秒</span></div>
                <p>{{ decision.rationale }}</p>
                {% if decision.reason_codes %}<div class="decision-meta">原因代码：{{ decision.reason_codes|join(", ") }}</div>{% endif %}
              </li>
            {% endfor %}
            </ol>
            {% else %}<div class="empty">该发现没有记录 Agent 决策。</div>{% endif %}
          </div>

          <div class="finding-block">
            <h4>支持证据与反证</h4>
            <div class="review-grid">
              <div class="review-column support">
                <strong>支持证据节点</strong>
                {% if finding.supporting_references %}<ul>{% for reference in finding.supporting_references %}<li class="mono">{{ reference }}</li>{% endfor %}</ul>{% else %}<p class="section-note">未记录支持证据节点。</p>{% endif %}
              </div>
              <div class="review-column counter">
                <strong>反证节点</strong>
                {% if finding.counter_references %}<ul>{% for reference in finding.counter_references %}<li class="mono">{{ reference }}</li>{% endfor %}</ul>{% else %}<p class="section-note">未记录反证节点。</p>{% endif %}
              </div>
            </div>
          </div>

          <div class="finding-block">
            <h4>修复建议</h4>
            <p class="remediation">{{ finding.remediation }}</p>
          </div>
        </div>
      </article>
      {% endfor %}
      {% else %}<div class="empty">本次运行未记录漏洞发现。</div>{% endif %}
    </section>

    <section aria-labelledby="diagnostics-heading">
      <h2 id="diagnostics-heading">诊断信息</h2>
      {% if report.diagnostics %}
      <ol class="diagnostic-list">
      {% for diagnostic in report.diagnostics %}
        <li class="diagnostic level-{{ diagnostic.level }}">
          <strong>{{ diagnostic_level_labels[diagnostic.level] }} | {{ diagnostic.code }}</strong>
          <p>{% if diagnostic.path %}<span class="mono">{{ diagnostic.path }}{% if diagnostic.line %}:{{ diagnostic.line }}{% endif %}</span>: {% endif %}{{ diagnostic.message }}</p>
        </li>
      {% endfor %}
      </ol>
      {% else %}<div class="empty">未输出诊断信息。</div>{% endif %}
    </section>
  </main>
  <footer><div class="shell">报告架构 {{ report.schema_version }} | AegisFlow {{ report.tool_version }}</div></footer>
</body>
</html>
"""

_ENVIRONMENT = Environment(
    autoescape=True,
    undefined=StrictUndefined,
    trim_blocks=True,
    lstrip_blocks=True,
)
_TEMPLATE = _ENVIRONMENT.from_string(_HTML_TEMPLATE)


def render_json(report: ReportEnvelope) -> str:
    """Render the validated envelope as canonical, stable JSON."""

    return report.canonical_json()


def _html_view(report: ReportEnvelope) -> dict[str, object]:
    data = report.canonical_data()
    severity_counts = {severity: 0 for severity in _SEVERITY_ORDER}
    for finding in data["findings"]:
        severity_counts[finding["severity"]] += 1
        supporting = {
            node_id
            for decision in finding["decisions"]
            for node_id in decision["supporting_node_ids"]
        }
        counter = {
            node_id
            for decision in finding["decisions"]
            for node_id in decision["counterevidence_node_ids"]
        }
        finding["supporting_references"] = sorted(supporting)
        finding["counter_references"] = sorted(counter)
    return {
        "report": data,
        "severity_counts": severity_counts,
        "severity_order": _SEVERITY_ORDER,
        "severity_labels": _SEVERITY_LABELS,
        "disposition_labels": _DISPOSITION_LABELS,
        "node_kind_labels": _NODE_KIND_LABELS,
        "relation_labels": _RELATION_LABELS,
        "agent_role_labels": _AGENT_ROLE_LABELS,
        "verdict_labels": _VERDICT_LABELS,
        "run_mode_labels": _RUN_MODE_LABELS,
        "diagnostic_level_labels": _DIAGNOSTIC_LEVEL_LABELS,
    }


def render_html(report: ReportEnvelope) -> str:
    """Render a self-contained report with all untrusted values escaped."""

    return _TEMPLATE.render(**_html_view(report))


def write_report(
    report: ReportEnvelope,
    output: Path,
    format: Literal["json", "html"],
) -> None:
    """Render and write a report, creating only the requested output directory."""

    renderers = {"json": render_json, "html": render_html}
    try:
        renderer = renderers[format]
    except KeyError as error:
        raise ValueError("format must be 'json' or 'html'") from error
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(renderer(report), encoding="utf-8", newline="\n")


__all__ = ["render_html", "render_json", "write_report"]
