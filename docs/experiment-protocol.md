# 对照实验与 Agent 复核协议

## 目的

满足“传统流程 vs AegisFlow”以及“offline vs agent”分开统计的要求。所有正式结论必须基于未参与规则调优的独立测试集，并记录版本、硬件、运行参数、人工确认标准和原始日志。

## 固定运行环境

- 工具版本：AegisFlow 0.1.0；
- Python：3.11 或更高版本；
- 运行平台：待提交前在固定机器补录；
- 样本：授权或脱敏的独立测试集；内置 16 个样例只能作为回归基线；
- 网络：离线模式禁止网络，Agent 模式必须记录服务端点和模型版本；
- 成本：记录输入/输出 token、单价和实际或估算费用。

## 对照组

传统组至少选择一种并固定版本：纯人工审计，或既有规则扫描流程。记录候选列表、确认结果、人工耗时和误报/漏报原因。AegisFlow 组使用相同输入，分别运行 `offline` 和 `agent`，不得更换真值或样本筛选规则。

## 指标口径

| 指标 | 定义 | 必存证据 |
|---|---|---|
| 漏洞发现率 | `TP / (TP + FN)` | 真值、匹配规则、FN 清单 |
| 误报率 | `FP / (TP + FP)` | FP 清单、人工复核记录 |
| 审计量级 | 文件数、有效代码行数、语言分布 | 输入清单、过滤日志 |
| 首个高危时长 | 扫描启动至首条高危发现 | 原始时间戳、运行日志 |
| 模型成本 | 请求数、输入/输出 token、单价和费用 | 配置、费用公式、响应 usage |
| 人机验证时间比例 | 人工复核时间 / 总审计时间 | 计时表、复核人记录 |

## 复现命令

```powershell
aegisflow benchmark .\benchmarks\fixtures --ground-truth .\benchmarks\ground_truth.json --output .\artifacts\benchmark-final.json
aegisflow scan .\benchmarks\fixtures --mode offline --format json --output .\artifacts\offline-report.json --fail-on none
aegisflow scan .\benchmarks\fixtures --mode agent --model-config .\config\model.example.toml --max-requests 8 --max-cost-usd 0.50 --format json --output .\artifacts\agent-report.json --fail-on none
```

`agent` 命令只有在获得外部服务授权、配置凭据和固定模型后才可执行。没有这些条件时，必须记录为 `not_run`，不能用离线结果代替。

## 当前已验证结果

内置回归基线：TP=8、FP=0、FN=0、Precision=1.000、Recall=1.000、F1=1.000、误报率=0.000。该数据来自 16 个内置样例，不能外推到真实代码库。独立测试集、传统对照组、人工计时和 `agent` 实测结果均待补录。

## 失败降级验收

模型超时、无效 JSON、未知证据节点、缺少凭据或预算耗尽时，结果必须变为 `needs_review`，不得静默确认。现有测试已覆盖这些路径；正式实验还需保留原始响应摘要、错误类型、预算使用量和人工处置结果。
