# 服务阶段发行所

离线服务发行控制面。三个入口分别是制品准入、阶段推进、恢复裁决；SQLite 保存制品、计划、固定副本批次、健康样本、恢复工单和原始事件。

运行：`python -m cloudroll all fixtures/demo.json --db demo.sqlite`。测试：`python -m unittest discover -s tests -v`。依赖仅 Python 标准库。首次打开数据库自动初始化。每个 fixture 含 `actions` 列表；业务拒绝返回结果码。重新演示请使用新的数据库路径。

三个入口各自可运行，例如 `python -m cloudroll artifact fixtures/artifact_normal.json --db artifact.sqlite`、`python -m cloudroll stage fixtures/stage_normal.json --db stage.sqlite`、`python -m cloudroll recovery fixtures/recovery_normal.json --db recovery.sqlite`。各入口另有同名 `failure` fixture，包含确实改变结论的错误身份、时间窗或未完成回执。

制品服务端依赖与存量客户端契约都须合格才能锁定发行窗。阶段成员一经开始固定，晚到副本不改变分母。阶段失败时恢复模块从兼容的历史稳定版本选择目标，全部补偿回执齐全才封卷；未知副本须单独纳管或隔离。

十个首版决策面分别是：依赖兼容准入、发行窗冲突锁定、制品撤销传播、阶段成员封存、窗口内健康裁定、回执超时停驻、回退目标裁定、补偿完成提交、存量客户端契约保留、游离副本接管。`artifact.py`、`stage.py`、`recovery.py` 保存各自的业务实体，`store.py` 把外部动作及结果与状态修改置于同一 SQLite 事务。`cli.py` 的 `audit` 在独立内存数据库中从 `command_events` 重跑所有动作，逐项比对结论和状态表；演示输出的 `audit.verified` 才代表此次状态可由证据重建。测试还刻意篡改一次状态，确认重放会报出分歧。

跨模块路径包括：候选计划锁定后基线或撤销版本变化会阻断阶段执行，但保留已部署副本来源；固定成员缺回执或观察窗内健康失败会创建恢复工单；恢复模块按当前依赖选取稳定版本，部分补偿或同服务游离副本会阻断关单，全部完成后才提交稳定指针。测试分别核对前后状态及审计重放。

后续边界：多服务依赖链发行、灰度群组自动选取、跨区域版本协商、容量预算联动发布、变更审批责任链、制品签名撤销、客户端自动迁移、多目标恢复演练。当前版本不实现。

## 跨区域写入连续性（本次新增）

发行所仍为每个服务保存一份基线与共同稳定指针，同时新增区域侧事实，解决华东（旧格式第 7 代）、华南（新格式第 8 代）断链后各自签出“第 8 代”（同代异摘要）以及客户写入承诺的兑现问题。

- 区域部署与租约：`stage.deploy` 只承认摘要与制品库一致的本地副本，`stage.lease`/`stage.admit` 才把它放进读写路由；没有本地已验证副本会得到 `region_not_deployed`。
- 事前策略：`stage.policy` 的 `single`（单区写，默认固定华东，华南只读）或 `bridge`（双写格式桥，两地可写）。断链用 `stage.link_down`/`region.reconnect` 记录。
- 跨区写入序列：`write.submit`/`write.commit` 为每笔保存源区域 `source_region`、区域源序号 `source_seq`、全局操作身份 `global_id` 与待复制序号 `pending_seq`，并维护 `region_sequence` 真实序号游标。单区写模式下非固定主区的写入只会被拒绝（`rejected`/`read_only`）或经 `write.stage` 明确暂存（`staged`，不确认、不占源序号），重连后可用 `write.flush` 提交。
- 未知提交恢复：确认回执丢失后 `write.recover`/`commit.status` 读取两区真实业务序号；只要有序号/已提交记录就判定 `committed`/`promised=true`，必须补送兑现；两区都查无此操作才是 `unknown`，可安全拒绝或由客户端重试。重复确认返回 `duplicate` 且不增加序号。
- 格式桥：`artifact.bridge` 登记可逆转换器；`bridge.prove` 逐笔核对两端是同一业务操作（全局身份与载荷摘要）。跨格式只有“转换可逆”或“逐笔桥证明”才能共同确认；旧格式副本不能覆盖新格式记录（`old_overwrites_new`）。
- 断链重连：`recovery.reconcile` 先逐笔分组、核对载荷与格式、列出可合并写入、缺失源序号（`missing_sequences`）和补送义务（`backfill`），保留两份第 8 代签发（`region_stable`/`issuances`）；`write.backfill` 完成补送后，`recovery.switch_pointer` 才提交共同指针。已确认的桥写入不会因事后把策略改成单区写而消失。
- 旧协议代理：`artifact.proxy` 可带区域/带宽，`artifact.proxy_path` 记录代理实际区域、可达性与带宽；到期时间只是必要证据，区域隔离或带宽为 0/不足会使 `artifact.plan`/`client_eligibility` 失败（`proxy_region_unreachable`/`proxy_bandwidth_insufficient`）。

所有新操作同样经 `apply_command` 幂等记录到 `command_events`，`audit` 在内存库重放并逐表比对（新表与兼容别名表都纳入）。`tests/test_region_continuity.py` 覆盖两种真实写入结果、同代异摘要、断链重连与缺失序号补送、旧代理断带、重复确认、未知提交（重启连接）恢复、区域租约与旧不覆新。
