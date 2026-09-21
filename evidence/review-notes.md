# project-02 交付复盘记录

## Prompt 分解

P1：首次 zserv 不可达或运行中连接断开时会进入可取消退避并在服务恢复后建立新的 ZAPI 会话，不再读取关闭通道形成忙循环。
P2：每个新会话重新完成版本协商、接口订阅和配置的 redistribute 订阅，旧会话的迟到消息不能修改当前状态。
P3：断线前从 Zebra 导入而新会话尚未重新通告的路由会被清理，其他来源的 BGP 路由不受影响。
P4：重连后从当前 RIB 重放应存在的 FIB 路由，并包含断线期间发生的新增、撤销和 best-path 变化且不重复下发。
P5：nexthop 可达性缓存按会话重建，当前路径需要的注册会重新发送，旧会话的 metric 或不可达状态不会泄漏。
P6：启用 MPLS label 管理时重新申请有效 label chunk 并恢复各 VRF 发布，局部失败保持未同步且可重试而不会误报健康。
P7：主动停止 BGP 或关闭 Zebra 集成会终止连接、退避和重放任务，停止后即使 zserv 恢复也不会自动连接。
P8：首次连接成功、未启用 NHT 或 MPLS、ZAPI 版本回退及正常增量收发的既有行为保持兼容。

## Prompt-Rubric 对齐表

P1 -> R1：原始 Prompt 明示的场景、边界或可观察结果由该 Rubric 直接验收。
P2 -> R2：原始 Prompt 明示的场景、边界或可观察结果由该 Rubric 直接验收。
P3 -> R3：原始 Prompt 明示的场景、边界或可观察结果由该 Rubric 直接验收。
P4 -> R4：原始 Prompt 明示的场景、边界或可观察结果由该 Rubric 直接验收。
P5 -> R5：原始 Prompt 明示的场景、边界或可观察结果由该 Rubric 直接验收。
P6 -> R6：原始 Prompt 明示的场景、边界或可观察结果由该 Rubric 直接验收。
P7 -> R7：原始 Prompt 明示的场景、边界或可观察结果由该 Rubric 直接验收。
P8 -> R8：原始 Prompt 明示的场景、边界或可观察结果由该 Rubric 直接验收。

双向覆盖结论：P1-P8 均有对应 Rubric，R1-R8 均可回指 Prompt 明示需求。无额外验收要求。

## 生产路径与生命周期审计

生产入口是 Zebra client 连接循环；状态 owner 是 zebraClient 会话 generation、sync bitmap、路由/nexthop 缓存和 MPLS label。API 边界是 ZAPI socket。顺序为拨号、协商、订阅、清理旧输入、重放、标记同步；停止会取消退避和重放。可控交错：令 SendIPRoute 在快照重放时返回错误，循环继续且 prepareSession 设置 syncedFIB，健康状态与 Zebra 实际路由不一致。

## Rubric 结果

```text
1 通过
2 通过
3 通过
4 未通过 RIB 重放中 SendIPRoute 错误只记录日志，prepareSession 仍把 FIB 类别标记为已同步
5 未通过 nexthop 重放中 SendNexthopRegister 错误只记录日志，prepareSession 仍把 nexthop 类别标记为已同步
6 未通过 初始 MPLS label chunk 请求失败后只记录错误，当前已连接会话不会重试且一直保持未同步
7 通过
8 通过
```
