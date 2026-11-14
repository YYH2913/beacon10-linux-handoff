# beacon10-linux-handoff

[English](README.md) | **简体中文**

把原厂签名 Linux 交接给 ARM64 Linux。

```text
原厂 U-Boot / bootipq
→ 原厂签名 Linux 5.4.164
→ 最小 SquashFS + PID1: b10-loader → beacon10-handoff.ko → ARM64 trampoline
→ 目标 Linux（EL1、MMU/cache 关闭、x0=DTB）
```

- 不换 U-Boot，不换 HLOS。
- 原厂内核照常启动，只跑最小启动根，充当过渡环境。
- 不先启动完整原厂系统再跑脚本。

## 范围

- **核心交接器**：校验 Image/DTB/载荷、SHA256、受控 RAM 分配与搬运、显式提交 ioctl、关停 DMA/CPU、Cortex-A73/EL1 trampoline。
- **启动根与工具**：PID1 loader、BusyBox/SSH 救援、原厂 ABI 配置生成、SquashFS 打包、载荷/安装包构造。
- **分区与迁移**：公开布局、离线 GPT 规划、普通文件迁移模型。实机安装入口默认禁用。
- **接收端**：只给接口和设计说明。目标驱动补丁、DTS、供电 helper、root-enter、fstools、boot-ACK 不在本仓库。

## 禁止操作

- 没有通用 `dd` 刷机命令。
- 不把 `bootstrap.squashfs` 传到原厂 Web 升级。
- 不把 `boot.bin` 写进 HLOS。
- 已迁移机器不再跑旧原厂布局/P26 恢复流程。

## 构建与离线检查

```bash
sudo apt-get install build-essential python3 device-tree-compiler libfdt1 \
  squashfs-tools gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu \
  libc6-dev-arm64-cross qemu-user-static fakeroot

git clone https://github.com/YYH2913/beacon10-linux-handoff.git
cd beacon10-linux-handoff
make host-tools arm64-tools check
```

`check` 检查生成的布局常量。测试脚本仅留本地，不加入提交；以上命令不连接或写入设备。

产物：

- `build/host/b10-loader`、`build/host/b10-install`。
- `build/arm64/` 静态 ARM64 工具。
- 原厂 `.ko` 与 `bootstrap.squashfs`：自备原厂备份、匹配头文件、BusyBox、Dropbear 和 SSH 公钥，按[构建说明](docs/build.md)生成，不进 release。

## 文档

- [架构与交接过程](docs/architecture.md)
- [构建与产物、烧录边界](docs/build.md)
- [分区布局、迁移顺序及恢复风险](docs/partitions-and-migration.md)
- [接收端适配思路与接口要求（无实现源码）](docs/receiver-design.md)
- [源码导出来源与初始摘要](docs/import-provenance.json)

核心代码在 `tools/beacon10/handoff/`。这是独立仓库，不修改原 QSDK14 工程。

## 许可

以 SPDX 为准：主要代码 GPL-2.0-only，少数规划工具 GPL-2.0+，见 [LICENSE](LICENSE)。
