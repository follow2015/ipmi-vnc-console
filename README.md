# KVM Hub

[![ci](https://github.com/follow2015/ipmi-vnc-console/actions/workflows/ci.yml/badge.svg)](https://github.com/follow2015/ipmi-vnc-console/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

一个本地 BMC KVM 控制台 PoC：Manager、Worker 与模拟 BMC 作为独立进程，演示从登录、资产授权、一次性票据、mTLS 兑换，到独立会话 Cookie、二进制画面/输入转发、租约、撤销与注销的完整控制面闭环。

**这是安全机制的参考实现，不是可部署的产品**：默认只启用合成设备，没有真实厂商 KVM 适配，也没有生产级隔离、SSO、KMS 或 PostgreSQL。

> 本仓是公开的源码发布镜像，由私有开发仓按白名单同步生成。内部设计稿、评审记录与真机证据不属于公开面；同步时会剥离开发注释并脱敏内部资产地址。

## 设计要点

| 维度 | 实现 |
|---|---|
| 控制面 | FastAPI Manager + aiohttp Worker + 模拟 BMC，内部端口强制客户端证书并校验实例证明 |
| 会话票据 | EdDSA 一次性票据，兑换后即消耗；重放与并行接入被拒绝且不影响原会话 |
| 浏览器隔离 | `__Host-` 前缀、Secure/HttpOnly/SameSite=Strict Cookie，CSP 与 CSRF 校验 |
| 资产占位 | SQLite 事务 + 唯一部分索引，清理未确认时保留占位，不按猜测时间自动放行 |
| 能力闸门 | `adapter_capability` 必须 verified、未过期、型号/固件/适配器精确匹配，默认拒绝；审批只能带外执行 |
| 可观测性 | 稳定错误码 → 唯一 HTTP 状态映射，`X-Trace-ID` 跨 Manager / Worker / 审计传播 |
| 清理语义 | 只有「请求从未发出 / 明确拒绝 / 已注销 / 人工放行并审计」才释放名额 |

## 运行

需要 Python 3.14，端口 `8443/8444/9443/10443` 空闲；服务只监听 `127.0.0.1`。端口被占用时可用 `KVMHUB_UI_PORT` / `KVMHUB_INTERNAL_PORT` / `KVMHUB_WORKER_PORT` / `KVMHUB_BMC_PORT` 整体平移。

```bash
python3.14 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
.venv/bin/python tools/bootstrap.py --directory .local-preview
.venv/bin/python -m kvmhub.run --directory .local-preview
```

打开 `https://localhost:8443`，登录口令在同目录的 `login-token`。浏览器需信任这次生成的测试 CA（`.local-preview/ca.pem`）；不要为了演示关闭浏览器的全局证书校验。

`bootstrap.py` 会在生成目录内写入短期测试 CA、服务端/客户端证书、签名与加密密钥、模拟设备凭据和数据库，并拒绝覆盖已有目录。运行目录含私钥，请使用 `.local*` 前缀（已被 `.gitignore` 忽略），不要提交或共享。

## 验证

```bash
make check                             # 安全门禁 + 全套测试，与 CI 同口径
.venv/bin/python -m pytest -q          # 全套自动测试
.venv/bin/python tools/gate.py         # 忽略规则 / 已入库密钥 / 错误码 / lockfile 漂移
```

测试覆盖数据库并发占位、票据重放、能力矩阵默认拒绝与回退、兑换失败后的可恢复性、mTLS 与证书错误时不发送凭据、Cookie 隔离、单条 WebSocket 断开可重连、跨组件 trace、错误码映射、人工放行审计与注销失败等路径。浏览器端到端验收需要另外安装 Playwright 与 Chromium（均不纳入仓库），可用 `make e2e` 一键编排。

`demos/redfish_probe.py` 是有界的只读 Redfish 探测工具：请求数、成员数与操作时间都有预算，输出只保留允许的字段与稳定错误码。它不批准适配器，也不把探测成功等同 KVM 支持。

## 当前边界

- 本地用户口令取代 SSO，用户会话保存在内存；本地密钥文件取代 KMS。
- SQLite 单 Manager 占位与审计；未实现 PostgreSQL/Alembic、outbox、Redis 或多 Worker 路由。
- 服务是不同进程但由同一 OS 用户运行，配置文件与密钥没有抵抗同用户进程读取的隔离。
- 真机适配器（passthrough / Supermicro X10 iKVM）是独立实验路径，默认配置下不可达；启用仍需精确能力条目、资产目标白名单与带外审批。
- 测试通过不等于厂商真机兼容；阶段 0/1 验收以真实设备结果为准。

## 许可证

Apache License 2.0，见 [LICENSE](LICENSE)。
