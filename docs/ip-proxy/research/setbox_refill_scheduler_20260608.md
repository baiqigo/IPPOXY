# Setbox Refill Scheduler 2026-06-08

## Goal

把 IPPOXY 的“持续抓节点”做成 setbox 上的短任务循环：

```text
Grok source discovery
-> candidate harvest
-> batch check
-> classification
-> latest clean files for Resin import
```

这不是全网扫描；只拉取公开 URL、官方 API、GitHub raw、订阅页面和既有候选文档。

## Current Implementation

- `tools/ip_grok_source_discovery.py`
  - 作用：用 Grok 16x Agent 搜索新的公开来源 URL。
  - 输出：`docs/ip-proxy/research/grok_ip_source_discovery_20260608.md` 和 runtime JSON/raw。
  - 运行频率建议：每 6 小时一次。
- `tools/ip_proxy_candidate_harvest.py`
  - 作用：抓取明确来源里的 TURN / SSTP / SOCKS5 候选，检测 clean 状态。
  - 关键参数：
    - `--run-id <id>`：每轮输出独立文件，避免覆盖历史。
    - `--max-check <n>`：每轮最多检测多少候选。
    - `--max-socks-per-source <n>`：限制大型 SOCKS 源，避免低质量候选淹没池子。
  - 输出：
    - `docs/ip-proxy/research/runtime/proxy_candidate_pool_<run_id>.json`
    - `docs/ip-proxy/research/runtime/proxy_candidate_check_<run_id>.json`
    - `docs/ip-proxy/research/runtime/proxy_candidate_check_<run_id>.md`
    - `*.latest.*` 指向最新一轮。
- `tools/ip_proxy_classify_clean.py`
  - 作用：按 `residential / static / risk_review` 分类 clean 候选。
  - 输出：
    - `docs/ip-proxy/resin/clean_candidate_classification_<run_id>.md`
    - `docs/ip-proxy/resin/residential_clean_candidates_<run_id>.txt`
    - `docs/ip-proxy/resin/static_clean_candidates_<run_id>.txt`
    - `docs/ip-proxy/resin/risk_review_clean_candidates_<run_id>.txt`
    - `*.latest.*` 指向最新一轮。
- `tools/ip_proxy_refill_once.sh`
  - 作用：setbox 单轮短任务入口。
  - 不长驻，不占用端口。

## Recommended Schedule

### Refill Check

建议每 30 分钟跑一轮：

```bash
cd /home/daytona/IPPOXY
MAX_CHECK=240 MAX_SOCKS_PER_SOURCE=200 WORKERS=10 TIMEOUT=12 \
  bash tools/ip_proxy_refill_once.sh
```

理由：

- cmliussss / VPNGate / GitHub raw 的节点波动明显，30 分钟足够及时。
- `MAX_CHECK=240` 在当前公共 checker 延迟下通常是几分钟级，不会形成持续压力。
- Resin 后续会做更短周期的本地健康检查，补池任务不需要每几分钟跑。

### Grok Source Discovery

建议每 6 小时跑一轮：

```bash
cd /home/daytona/IPPOXY
GROK_API_KEY=<key> WITH_GROK=1 MAX_CHECK=240 MAX_SOCKS_PER_SOURCE=200 \
  bash tools/ip_proxy_refill_once.sh
```

理由：

- Grok 负责发现新公开来源，不是检测节点；来源变化慢于节点存活。
- 6 小时能覆盖 F0rc3Run 这类自动仓库刷新周期。
- 每 30 分钟都跑 Grok 成本高，收益低。

## Cron Example

```cron
*/30 * * * * cd /home/daytona/IPPOXY && MAX_CHECK=240 MAX_SOCKS_PER_SOURCE=200 WORKERS=10 TIMEOUT=12 bash tools/ip_proxy_refill_once.sh >> /home/daytona/IPPOXY/captures/ip-refill.log 2>&1
7 */6 * * * cd /home/daytona/IPPOXY && GROK_API_KEY=<key> WITH_GROK=1 MAX_CHECK=240 MAX_SOCKS_PER_SOURCE=200 WORKERS=10 TIMEOUT=12 bash tools/ip_proxy_refill_once.sh >> /home/daytona/IPPOXY/captures/ip-refill-grok.log 2>&1
```

## Current Verification

- `python tools/ip_grok_source_discovery.py` succeeded once and extracted 24 URLs.
- `python tools/ip_proxy_candidate_harvest.py --harvest-only --max-socks-per-source 200` found 1717 candidates:
  - TURN: 827
  - SSTP: 430
  - SOCKS5: 460
- `python tools/ip_proxy_candidate_harvest.py --run-id refill_sample_20260608_120 --workers 10 --timeout 12 --max-socks-per-source 200 --max-check 120` checked a sample batch:
  - checked: 120
  - success: 79
  - clean: 37
- Classification for that sample:
  - residential: 23
  - static: 9
  - risk_review: 5
- Windows-side `bash -n tools/ip_proxy_refill_once.sh` could not run because local WSL has no `/bin/bash`; verify shell syntax on setbox/Linux before installing cron.

## Next Step

把 `*.latest.*` clean 文件接入 Resin import/update，并让 Resin 的 health check / ephemeral eviction 负责运行态坏节点剔除。
