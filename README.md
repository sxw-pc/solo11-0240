# 服务阶段发行所

离线服务发行控制面。三个入口分别是制品准入、阶段推进、恢复裁决；SQLite 保存制品、计划、固定副本批次、健康样本、恢复工单和原始事件。

运行：`python -m cloudroll all fixtures/demo.json --db demo.sqlite`。测试：`python -m unittest discover -s tests -v`。依赖仅 Python 标准库。首次打开数据库自动初始化。每个 fixture 含 `actions` 列表；业务拒绝返回结果码。重新演示请使用新的数据库路径。

三个入口各自可运行，例如 `python -m cloudroll artifact fixtures/artifact_normal.json --db artifact.sqlite`、`python -m cloudroll stage fixtures/stage_normal.json --db stage.sqlite`、`python -m cloudroll recovery fixtures/recovery_normal.json --db recovery.sqlite`。各入口另有同名 `failure` fixture，包含确实改变结论的错误身份、时间窗或未完成回执。

制品服务端依赖与存量客户端契约都须合格才能锁定发行窗。阶段成员一经开始固定，晚到副本不改变分母。阶段失败时恢复模块从兼容的历史稳定版本选择目标，全部补偿回执齐全才封卷；未知副本须单独纳管或隔离。

十个首版决策面分别是：依赖兼容准入、发行窗冲突锁定、制品撤销传播、阶段成员封存、窗口内健康裁定、回执超时停驻、回退目标裁定、补偿完成提交、存量客户端契约保留、游离副本接管。`artifact.py`、`stage.py`、`recovery.py` 保存各自的业务实体，`store.py` 把外部动作及结果与状态修改置于同一 SQLite 事务。`cli.py` 的 `audit` 在独立内存数据库中从 `command_events` 重跑所有动作，逐项比对结论和状态表；演示输出的 `audit.verified` 才代表此次状态可由证据重建。测试还刻意篡改一次状态，确认重放会报出分歧。

跨模块路径包括：候选计划锁定后基线或撤销版本变化会阻断阶段执行，但保留已部署副本来源；固定成员缺回执或观察窗内健康失败会创建恢复工单；恢复模块按当前依赖选取稳定版本，部分补偿或同服务游离副本会阻断关单，全部完成后才提交稳定指针。测试分别核对前后状态及审计重放。

真实曝光与跨设备身份（`exposure.py`、`identity.py`，配合改写后的 `route_delivery.py`、`trial_sample.py`）解决“路由已发出 ≠ 屏幕已呈现”和“设备 ≠ 独立客户”两个问题。`route.issue` 现在记录登录会话与区域，未产生曝光的路由可由 `route.withdraw` 撤回；一旦曝光引用了路由，撤回被拒绝，改摘要也会触发 `route_receipt_conflict`，样本所属版本因此无法被事后重贴。`exposure.render_receipt` 把物理设备密钥、登录会话、实际显示字节摘要、呈现分钟和客户端确认绑定成一张呈现收据并生成不可变 `exposure`（身份为“设备+摘要”）；`exposure.report_render_event` 接收原始信号，`prefetch` 只入原始事件表、永不产生曝光，重试与同页复扫返回 `already_exposed`，重复收据返回 `duplicate_exposure`，都不制造第二次曝光。断电重开后迟到的重复收据同样不能抹掉或复制既有曝光。

跨设备身份以不携带版本信息的身份挑战完成：`identity.freeze_challenge` 先冻结两台共用会话设备的呈现，并要求独立分支（d1/d2 分开）与四人统一分支（C/E 新版、D/F 旧版）都通过 `check_slots` 可行性核验——每分支必须两名独立新版、两名独立旧版、每组各覆盖东西两区、四份可计入样本且每台设备都有未撤回的可用路由；任一分支不可行则挑战不得发出。`identity.resolve_challenge` 仅接受 `independent`、`same`、`no_answer` 三种回报并只执行对应一支：独立时允许 `trial.select_branch=pair`（d1 旧、d2 新、C 新、F 旧）；同一人或无答复时 pair 分支被拒绝，只能走 unified（C、E、D、F）。挑战期间缓存提前呈现会在收据上记 `frozen_at_render`；若随后证实同人且其历史同时含新旧两版，`taint_person` 保留两份原件、写入 `contamination_record` 并把样本置为不可计入，再由未曝光独立候补补位；候补不足时 `trial.verdict` 报告 `uncovered_cells`、本轮不可比较，绝不凑满四份。

`trial.register` 把样本登记与已确认呈现事实放在同一事务原子提交（可传既有收据 id，也可内联呈现证据），臂别由实际显示摘要推导而非路由标签；显示版本与分支槽位冲突时拒绝注册而不是改标签。仅账户名或设备不同不能拆开同一真实人，样本按解析后的人去重，`verdict` 只在四个独立人恰好覆盖四个“臂×区域”格子时给出 `comparable`。新增 fixture `exposure_pair.json`（独立回报分支）与 `exposure_contamination.json`（缓存提前呈现+同人污染+统一分支补位）可经 `python -m cloudroll exposure <fixture> --db <path>` 运行，独立测试见 `tests/test_exposure_identity.py`。

后续边界：多服务依赖链发行、灰度群组自动选取、跨区域版本协商、容量预算联动发布、变更审批责任链、制品签名撤销、客户端自动迁移、多目标恢复演练。当前版本不实现。
