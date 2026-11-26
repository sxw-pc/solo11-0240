# 服务阶段发行所

离线服务发行控制面。三个入口分别是制品准入、阶段推进、恢复裁决；SQLite 保存制品、计划、固定副本批次、健康样本、恢复工单和原始事件。

运行：`python -m cloudroll all fixtures/demo.json --db demo.sqlite`。测试：`python -m unittest discover -s tests -v`。依赖仅 Python 标准库。首次打开数据库自动初始化。每个 fixture 含 `actions` 列表；业务拒绝返回结果码。重新演示请使用新的数据库路径。

三个入口各自可运行，例如 `python -m cloudroll artifact fixtures/artifact_normal.json --db artifact.sqlite`、`python -m cloudroll stage fixtures/stage_normal.json --db stage.sqlite`、`python -m cloudroll recovery fixtures/recovery_normal.json --db recovery.sqlite`。各入口另有同名 `failure` fixture，包含确实改变结论的错误身份、时间窗或未完成回执。

制品服务端依赖与存量客户端契约都须合格才能锁定发行窗。阶段成员一经开始固定，晚到副本不改变分母。阶段失败时恢复模块从兼容的历史稳定版本选择目标，全部补偿回执齐全才封卷；未知副本须单独纳管或隔离。

## 对外发行证明

新增两个标准库模块：

- `cloudroll/external_attest.py`：绑定原始命令链、时点人口见证、代理到期、计划窗、裁决、内部重放状态根和不可变证书字节账本；支持受监管审计室证明、公开隐私证明、验证、发布幂等、撤回、重签发和代理实际中断的精确撤回范围。
- `cloudroll/privacy_release.py`：Pedersen 隐藏承诺、可公开验证的区间/覆盖关系证明，以及跨证书线性差量和时间谓词推断控制。

两种证明不是同一 JSON 删字段：

- `audited_service_compliance` 工作底稿仅在客户隐私官批准的受控审计路径生成，包含按服务列明的逐协议真实人数和代理记录，审计室可在内存库独立重放；`buyer_service_compliance` 是给采购方的服务列明副本，保留服务粒度和隐藏人口证明但不含真实人数。
- `public_privacy_compliance` 不含服务名、协议号或真实人数；每个发行批次使用新的承诺随机化因子，并默认只允许粗粒度批次窗口。后续相邻窗口或协议/分钟级查询会被 `InferenceGuard` 拒绝，除非作为通过联合泄露控制的显式联合证明发布。

常用 Python API：`issue_audited_certificate`、`issue_public_certificate`、`verify_certificate`、`publish_certificate`、`revoke_certificate`、`reissue_certificate`、`record_proxy_outage`、`outage_scope`。命令示例：

```bash
python -m cloudroll attest audited release.sqlite audited.json --service svc
python -m cloudroll attest buyer release.sqlite buyer.json --service svc
python -m cloudroll attest public release.sqlite public.json --window-id coarse-batch
python -m cloudroll attest verify public.json
```

同一 `submission_id` 失联重试只返回已存证书；同一提交号若对应矛盾字节会被拒绝。撤回和重签发不覆盖历史外部字节。代理中断只撤回计划窗与中断区间的精确交集，原始 `locked` 裁决和见证仍保留。


十个首版决策面分别是：依赖兼容准入、发行窗冲突锁定、制品撤销传播、阶段成员封存、窗口内健康裁定、回执超时停驻、回退目标裁定、补偿完成提交、存量客户端契约保留、游离副本接管。`artifact.py`、`stage.py`、`recovery.py` 保存各自的业务实体，`store.py` 把外部动作及结果与状态修改置于同一 SQLite 事务。`cli.py` 的 `audit` 在独立内存数据库中从 `command_events` 重跑所有动作，逐项比对结论和状态表；演示输出的 `audit.verified` 才代表此次状态可由证据重建。测试还刻意篡改一次状态，确认重放会报出分歧。

跨模块路径包括：候选计划锁定后基线或撤销版本变化会阻断阶段执行，但保留已部署副本来源；固定成员缺回执或观察窗内健康失败会创建恢复工单；恢复模块按当前依赖选取稳定版本，部分补偿或同服务游离副本会阻断关单，全部完成后才提交稳定指针。测试分别核对前后状态及审计重放。

后续边界：多服务依赖链发行、灰度群组自动选取、跨区域版本协商、容量预算联动发布、变更审批责任链、制品签名撤销、客户端自动迁移、多目标恢复演练。当前版本不实现。
