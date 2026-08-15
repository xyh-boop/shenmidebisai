# 基准测试方法

## 样本集

内置样本集包含 16 个相互独立的文件：Python 和 JavaScript 中四类漏洞各有一个易受攻击样例和一个结构相近的安全样例。8 个漏洞样例记录在 `benchmarks/ground_truth.json` 中；安全样例不包含预期发现。

| 规则 | CWE | Python | JavaScript |
|---|---|---:|---:|
| `AF-CMD-001` | CWE-78 | 漏洞 + 安全 | 漏洞 + 安全 |
| `AF-SQL-001` | CWE-89 | 漏洞 + 安全 | 漏洞 + 安全 |
| `AF-PATH-001` | CWE-22 | 漏洞 + 安全 | 漏洞 + 安全 |
| `AF-DESER-001` | CWE-502 | 漏洞 + 安全 | 漏洞 + 安全 |

安全近似样例覆盖常量命令、参数化 SQL、`basename` 路径收敛和仅解析数据的 JSON。预期结果保存在源代码注释之外，避免与样例文本形成简单耦合。

## 评分方法

真阳性需要同时满足：规则 ID 一致、规范化仓库相对路径一致、行号范围存在重叠。重复发现指纹仅计一次。报告中未匹配的发现为假阳性，真值中未匹配的条目为假阴性。

```text
precision = TP / (TP + FP)
recall = TP / (TP + FN)
F1 = 2 * precision * recall / (precision + recall)
false_discovery_rate = FP / (TP + FP)
```

这里的 `false_discovery_rate` 是错误发现率 FDR，不是经典假阳性率 FPR。当前基准没有定义完整的 TN 单元，因此不计算、不宣称 FPR；没有预测阳性时 FDR 按契约记为 `0.0`。文档中的 FP 仅表示与独立真值不匹配的预测发现。

报告还会记录扫描文件数与行数、耗时、首个高危发现时间、候选与处置结果数量、人工复核数量、提供方请求数、令牌数和预估美元成本。

## 复现方式

```powershell
aegisflow benchmark .\benchmarks\fixtures --ground-truth .\benchmarks\ground_truth.json --output .\artifacts\benchmark.json
```

请记录 AegisFlow 版本、Python 版本、操作系统、处理器、运行配置以及是否启用 Agent 模式。离线运行是规范基线。模型辅助的变化必须单独报告，因为模型版本和输出可能变化。

## 结果解读边界

这是一个小型回归与演示样本集，并非对真实世界通用准确率的估计。它主要证明已声明规则能够检测代表性的本地数据流，并抑制成对的安全近似样例。只有在加入版本化公开样本集和未参与调优的留出集后，才能扩展相关结论。
