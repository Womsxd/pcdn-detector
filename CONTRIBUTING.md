# Contributing to pcdn-detect

Thanks for taking the time to contribute! This document explains how to report
issues, propose changes, and get your work merged. It applies to everyone —
please read it before opening a pull request (PR).

[简体中文](#为本项目做出贡献)

---

## Contributor License Agreement (required)

Before your contribution can be accepted, you must agree to the project's
[Contributor License Agreement](CLA.md).

**By opening a pull request, you confirm that you have read the CLA and agree
to its terms for your present and future contributions.** You do not need to
sign any separate document. A PR that does not satisfy the CLA requirement will
not be merged.

In short, the CLA lets the maintainers and administrators of the project — now
and in the future — relicense your contributions under any
[OSI-approved license](https://opensource.org/licenses). Relicensing your
contribution under a non-OSI (for example proprietary) license requires your
separate explicit authorization.

## Developer Certificate of Origin (required)

Every commit in your pull request must be signed off to certify the
[Developer Certificate of Origin](https://developercertificate.org/) (DCO).
Add a `Signed-off-by` line with your name (the name or handle you go by) and an
email address as the last line of the commit message:

```
feat(firewall): support nftables sets in inet family

Signed-off-by: Jane Doe <jane@example.com>
```

`git commit -s` adds the line automatically, using the name and email from your
Git configuration (set them with `git config user.name` and
`git config user.email`). To add the line to commits that are missing it, run
`git rebase --signoff main`.

The sign-off only needs to identify you — a name or handle together with an
email address is enough; it does not have to be your legal name. By signing
off, you certify that you wrote the contribution or otherwise have the right to
submit it under the project's license. The DCO is a per-commit confirmation and
is required **in addition to** the CLA above; a PR whose commits are not signed
off will not be merged.

## Reporting issues

- Search the existing issues first to avoid duplicates.
- For a bug, include: the version (`pcdn-detect -v`), the OpenWrt / distribution
  version and CPU architecture (`cat /proc/cpuinfo`, `opkg print-architecture`),
  the interface you capture on, the storage / firewall backend in use
  (`hook` / `iptables` / `nftables`), and clear steps to reproduce.
- Attach the relevant log lines, preferably with `[log] level = "info"` (or
  `"debug"`) enabled. **Redact MAC addresses and public IP addresses** before
  pasting logs, or use `-H` / `--hide-address`.
- For a feature request, describe the use case and the behaviour you expect.
- Do not report security issues in a public issue — contact the maintainer
  privately instead.

## Development setup

The build instructions live in the [README](README.md#编译). The short version:

```bash
git clone https://cnb.cool/womsxd/pcdn-detector.git
cd pcdn-detect
make build          # -> bin/pcdn-detect
```

Requirements: Go 1.26 or newer (see `go.mod`). No CGO, libpcap or Android /
Gradle toolchain is involved — capture is implemented directly on AF_PACKET, so
a plain Go toolchain is enough to build and cross-compile.

`make build` produces a binary for the host, and the architecture targets
(`make mipsle`, `make mips`, `make arm`, `make arm64`, `make amd64`) produce
static OpenWrt binaries under `bin/`. If you touched the HTTP layer, also check
the reduced build: `make nohttp-build` (it must still compile with
`-tags nohttp`).

Running the binary for real requires `root` or `CAP_NET_RAW` and a LAN-side
interface such as `br-lan`. Unit tests do **not** need privileges or a real
network interface.

## Making changes

1. Fork the repository and create a branch off `main`, for example
   `fix/nftables-timeout` or `feat/upnp-whitelist`.
2. Keep the change focused. One logical change per PR is much easier to review.
3. Match the existing style: `gofmt`-formatted Go, Chinese package / symbol
   comments (as in the rest of `internal/`), and comments only where the logic
   is not self-evident. Keep the `internal/<area>` split — `capture`,
   `detector`, `filter`, `firewall`, `blocker`, `httpapi`, `config` — instead of
   adding cross-cutting code to `cmd/pcdn-detect`.
4. Add or update tests (`*_test.go` next to the package) for behaviour you
   change.
5. Update the documentation when your change affects user-visible behaviour:
   `README.md` for options and defaults, and the matching page under `docs/`
   (`memory.md`, `filter.md`, `firewall.md`, `upnp.md`, `http.md`). The default
   config template in `internal/config/template.go` must stay in sync with any
   new or changed config key. Documentation must describe what the code
   actually does — do not claim capabilities or protections that are not
   implemented.

## Before you open a pull request

Run the same checks locally, and make sure they pass:

```bash
gofmt -l .        # must print nothing
go vet ./...
go test ./...
make build        # and `make mipsle` / `make nohttp-build` if you touched
                  # capture, firewall or the HTTP layer
```

If formatting, vet or tests fail, fix them before requesting review.

## Pull request process

- Open the PR against the `main` branch.
- Use a clear title and describe **what** changed and **why**. Link the issue
  it fixes (`Fixes #123`) where applicable.
- Use Conventional Commit style for the PR title/commits (`feat:`, `fix:`,
  `docs:`, `refactor:`, `test:`, `ci:`, `chore:`), optionally with a scope,
  e.g. `fix(firewall): …`, `refactor(detector): …`.
- Confirm in the PR description that you agree to the CLA.
- Sign off every commit with a `Signed-off-by` line (see above).
- Keep the branch up to date with `main`; resolve conflicts yourself.
- Respond to review feedback. Reviewers may request changes, and a maintainer
  makes the final decision on whether a PR is merged.

---

# 为本项目做出贡献

感谢您愿意花时间做出贡献！本文档说明如何报告问题、提交改动，以及如何让您的改动被合并。
它适用于所有人——在发起 Pull Request（PR）之前，请先阅读本文档。

[English](#contributing-to-pcdn-detect)

---

## 贡献者许可协议（必需）

在接受您的贡献之前，您必须同意本项目的[贡献者许可协议](CLA.md)。

**发起 Pull Request 即表示您确认已阅读 CLA，并同意其条款适用于您当前及未来的贡献。**
无需另行签署任何单独文件。不满足 CLA 要求的 PR 将不会被合并。

简言之，CLA 允许本项目的维护者与管理者（当前及未来）将您的贡献内容按任意
[OSI 批准许可证](https://opensource.org/licenses)进行再许可；若要以非 OSI（例如专有）
许可证再许可您的贡献，须另行取得您的明确授权。

## 开发者原创声明（DCO，必需）

Pull Request 中的每一个提交都必须签署，以证明遵守
[开发者原创声明](https://developercertificate.org/)（Developer Certificate of
Origin，DCO）。请在提交信息（commit message）的最后一行加上 `Signed-off-by`，内容为
您的称呼（您使用的名字或网名）与邮箱：

```
feat(firewall): 支持 inet family 的 nftables 集合

Signed-off-by: 张三 <zhangsan@example.com>
```

`git commit -s` 会自动添加该行，姓名与邮箱取自 Git 配置（请先用 `git config user.name`
与 `git config user.email` 设置）。若已有提交缺少该行，可运行
`git rebase --signoff main` 补上。

签署行只需能标识您本人——一个称呼或网名加上邮箱即可，无需使用法定姓名。签署即表示
您证明该贡献由您本人创作，或您有权按本项目许可证提交它。DCO 是对每个提交的确认，与
上述 CLA **同时**适用；未签署的 PR 将不会被合并。

## 报告问题

- 请先搜索已有 issue，避免重复。
- 报告 bug 时请提供：版本号（`pcdn-detect -v`）、OpenWrt / 发行版版本与 CPU 架构
  （`cat /proc/cpuinfo`、`opkg print-architecture`）、抓包使用的网卡、所用防火墙后端
  （`hook` / `iptables` / `nftables`），以及清晰的可复现步骤。
- 请附上相关日志，最好开启 `[log] level = "info"`（或 `"debug"`）。粘贴前请**隐去 MAC
  与公网 IP**，或使用 `-H` / `--hide-address` 运行。
- 功能建议请描述使用场景与期望行为。
- 安全相关问题请勿在公开 issue 中报告，请私下联系维护者。

## 开发环境

构建步骤见 [README](README.md#编译)。简要流程：

```bash
git clone https://cnb.cool/womsxd/pcdn-detector.git
cd pcdn-detect
make build          # 产出 bin/pcdn-detect
```

环境要求：Go 1.26 及以上（见 `go.mod`）。本项目不涉及 CGO、libpcap 或 Android / Gradle
工具链——抓包直接基于 AF_PACKET 实现，因此只需 Go 工具链即可构建与交叉编译。

`make build` 构建本机可执行文件；各架构目标（`make mipsle`、`make mips`、`make arm`、
`make arm64`、`make amd64`）会在 `bin/` 下产出可静态部署到 OpenWrt 的二进制。若您改动了
HTTP 相关代码，请同时确认精简构建可用：`make nohttp-build`（必须以 `-tags nohttp` 编译
通过）。

实际运行二进制需要 `root` 或 `CAP_NET_RAW`，并指定 LAN 侧网卡（如 `br-lan`）。单元测试
**不需要**特权或真实网卡。

## 提交改动

1. Fork 仓库并从 `main` 创建分支，例如 `fix/nftables-timeout` 或
   `feat/upnp-whitelist`。
2. 保持改动聚焦。一个 PR 只做一件事，更易于评审。
3. 遵循既有风格：Go 代码需通过 `gofmt`；包与导出符号的注释使用中文（与 `internal/`
   下现有代码一致）；仅在逻辑不自明处添加注释。请保持 `internal/<模块>` 的职责划分
   （`capture`、`detector`、`filter`、`firewall`、`blocker`、`httpapi`、`config`），不要把
   横跨各模块的代码堆到 `cmd/pcdn-detect`。
4. 对您改动的行为补充或更新测试（与包同目录的 `*_test.go`）。
5. 当改动影响用户可见行为时，请同步更新文档：选项与默认值改 `README.md`，对应细节改
   `docs/` 下的相应页面（`memory.md`、`filter.md`、`firewall.md`、`upnp.md`、`http.md`）；
   新增或修改配置项时，`internal/config/template.go` 中的默认配置模板必须同步。文档必须
   如实描述代码的实际行为，不得宣称尚未实现的能力或保护措施。

## 发起 Pull Request 之前

请在本地运行以下检查并确保全部通过：

```bash
gofmt -l .        # 应无任何输出
go vet ./...
go test ./...
make build        # 若改动了抓包 / 防火墙 / HTTP 层，另跑 `make mipsle`、
                  # `make nohttp-build`
```

若格式、vet 或测试失败，请先修复再请求评审。

## Pull Request 流程

- 向 `main` 分支发起 PR。
- 使用清晰的标题，并说明**改了什么**以及**为什么**。若相关，请关联对应 issue
  （`Fixes #123`）。
- PR 标题/提交信息请使用 Conventional Commits 风格（`feat:`、`fix:`、`docs:`、
  `refactor:`、`test:`、`ci:`、`chore:`），可附带作用域，例如 `fix(firewall): …`、
  `refactor(detector): …`。
- 在 PR 描述中确认您同意 CLA。
- 为每个提交添加 `Signed-off-by` 签署行（见上）。
- 保持分支与 `main` 同步，并自行解决冲突。
- 回应评审意见。评审者可能要求修改，最终是否合并由维护者决定。
