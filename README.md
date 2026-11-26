# 服务阶段发行所

离线服务发行控制面。三个入口分别是制品准入、阶段推进、恢复裁决；SQLite 保存制品、计划、固定副本批次、健康样本、恢复工单和原始事件。

运行：`python -m cloudroll all fixtures/demo.json --db demo.sqlite`。测试：`python -m unittest discover -s tests -v`。依赖仅 Python 标准库。首次打开数据库自动初始化。每个 fixture 含 `actions` 列表；业务拒绝返回结果码。重新演示请使用新的数据库路径。

三个入口各自可运行，例如 `python -m cloudroll artifact fixtures/artifact_normal.json --db artifact.sqlite`、`python -m cloudroll stage fixtures/stage_normal.json --db stage.sqlite`、`python -m cloudroll recovery fixtures/recovery_normal.json --db recovery.sqlite`。各入口另有同名 `failure` fixture，包含确实改变结论的错误身份、时间窗或未完成回执。

制品服务端依赖与存量客户端契约都须合格才能锁定发行窗。阶段成员一经开始固定，晚到副本不改变分母。阶段失败时恢复模块从兼容的历史稳定版本选择目标，全部补偿回执齐全才封卷；未知副本须单独纳管或隔离。

十个首版决策面分别是：依赖兼容准入、发行窗冲突锁定、制品撤销传播、阶段成员封存、窗口内健康裁定、回执超时停驻、回退目标裁定、补偿完成提交、存量客户端契约保留、游离副本接管。`artifact.py`、`stage.py`、`recovery.py` 保存各自的业务实体，`store.py` 把外部动作及结果与状态修改置于同一 SQLite 事务。`cli.py` 的 `audit` 在独立内存数据库中从 `command_events` 重跑所有动作，逐项比对结论和状态表；演示输出的 `audit.verified` 才代表此次状态可由证据重建。测试还刻意篡改一次状态，确认重放会报出分歧。

跨模块路径包括：候选计划锁定后基线或撤销版本变化会阻断阶段执行，但保留已部署副本来源；固定成员缺回执或观察窗内健康失败会创建恢复工单；恢复模块按当前依赖选取稳定版本，部分补偿或同服务游离副本会阻断关单，全部完成后才提交稳定指针。测试分别核对前后状态及审计重放。

## 迟到原件、承诺与后继因果

成员、制品摘要、观察窗、失败预算和承诺策略在 `stage.start` 时封存（`stage.policy`、`stage.late_until_ts`，计划也可用 `commit_policy` 预设）。`stage.sample` 一律采入固定成员的原件，只有封存窗内、摘要正确的最新样本参与裁定，因此上传较晚但 `at` 属于原窗口的真实故障页不会被忽略，非成员与错误摘要不会改变成员数或结论。

两种获准做法都可复演：

- **等窗后正式承诺（wait/deferred）**：第 5 分钟证据齐全但迟到上限未结束时，`stage.decide`/`stage.observe` 只留下 `observing`（等同 `provisional`）临时观察与 `commitment(kind='observation')`，阶段不 `passed`，第二阶段 `stage.start` 以 `previous_stage_not_passed`/`commitment_not_final` 拒绝，事实中没有第二阶段部署；第 6 分钟故障原件到齐后裁定 `failed` 并建立 `rec-<stage>`。
- **可撤回的预备流量承诺（revocable/canary）**：第 5 分钟可 `stage.decide(policy='revocable')` 或 `stage.commit(revocable=True)`，写入可撤回的 `commitment(kind='canary',status='revocable')` 且阶段 `passed`，第二阶段真实启动并保留回执/流量。迟到故障经再次 `stage.decide` 或 `stage.reconsider` 重审后：原阶段置 `failed`、承诺置 `withdrawn`，已启动后继（及成员）置 `frozen` 但成员、回执、流量记录一律不删，同一因果恢复单 `rec-<first>` 承担全链补偿，并在 `obligation` 中为已部署实物副本与已承接流量记账（`stage.traffic` 可记实际流量）。

`stage.rerelease`/`artifact.recheck` 重新核对发行窗、存量客户端代理覆盖与制品撤销；`recovery.stable` 在存在 `running/observing/frozen` 后继时只写 `stable_history` 候选史、不移动 `stable` 指针（返回 `successor_still_running`），补偿封卷、后继 `compensated` 后指针才允许前进。`store.py` 以增量列、`commitment/traffic_ledger/obligation/stage_revision` 表和兼容只读视图保存这些事实，并对旧库做幂等 `ALTER` 迁移；所有写操作仍与 `command_events` 同事务，重送同一 `request_id` 返回原结论，关闭重开与 `cli.audit` 重放得到一致历史。

后续边界：多服务依赖链发行、灰度群组自动选取、跨区域版本协商、容量预算联动发布、变更审批责任链、制品签名撤销、客户端自动迁移、多目标恢复演练。当前版本不实现。
