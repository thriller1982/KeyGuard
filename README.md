# KeyGuard v3.0.0

KeyGuard 是一个基于 Python 和 PySide6 的便携式本地密码管理器。

> **一个 KeyGuard EXE、一个加密的 `.kgvault` 文件和主密码，即可读取完整密码库。**

保险库是自包含文件：条目、偏好设置、回收站条目、KDF 参数及盐值都加密保存在同一个 `.kgvault` 中，适合放在 U 盘、移动硬盘或网盘同步文件夹中使用。程序不依赖在线账户或远程服务。

## 当前版本

- 产品版本：`3.0.0`
- 文件版本：`3.0.0`
- 产品名称：`KeyGuard`
- 版权：`Copyright © 2026 thriller1982. All rights reserved.`

Windows 版本资源由 `version_info.txt` 提供，并通过 `KeyGuard.spec` 写入打包后的 EXE。

## 功能

- 新建或打开独立的 `.kgvault` 加密保险库
- 保存名称、网址、用户名、密码、分类、备注和最后修改时间
- 搜索及按分类筛选条目
- 密码生成器与密码强度提示
- **2FA 双因素身份验证器**（TOTP 动态验证码生成与自动倒计时刷新）
- **密码修改历史**，每个条目保留最多 10 条旧密码
- **安全回收站机制**（误删条目移入回收站，支持精确搜索、单项/批量恢复、彻底删除与清空）
- **表格自适应**，列宽随窗口缩放自适应权重分布，并支持拖拽记忆
- Markdown、CSV、JSON 导入与导出
- 中英文界面（支持跟随系统或手动切换）
- 可配置自动锁定时间（1/5/15/30 分钟或永不锁定）
- **原地原子保存**（In-place Atomic Save），保障多端同步稳定与断电数据完整
- 修改主密码时同步重新加密当前数据及回收站条目
- Windows `.kgvault` 文件关联（仅打包后的 EXE）

## 运行环境

- Python 3.14
- PySide6
- cryptography 48.0 或更高版本（需要 Argon2id 支持）

安装运行依赖：

```powershell
python -m pip install -r requirements.txt
```

源码启动：

```powershell
python main.py
```

打开指定保险库：

```powershell
python main.py "D:\Vaults\personal.kgvault"
```

打包后的调用方式相同：

```powershell
KeyGuard.exe "E:\Vaults\personal.kgvault"
```

## 启动流程

程序按以下优先级决定要打开的保险库：

1. 命令行提供了有效文件路径时，直接进入该文件的解锁流程。
2. 检测到旧版 `passwords.json` 时，提示输入原主密码并自动迁移到 v3 `.kgvault`。
3. 扫描 EXE 或源码所在目录：
   - 恰好存在一个有效 `.kgvault` 时，直接进入解锁流程。
   - 没有或存在多个保险库时，显示“新建/打开”选择器。

新建保险库时，默认路径为程序所在目录下的 `KeyGuard.kgvault`，用户可以选择其他位置。

## 核心机制

### 2FA 动态身份验证器（TOTP）

主界面顶部提供独立的 2FA 动态口令工具：

- 遵循 RFC 6238 国际标准，支持常见的 6 位数字 TOTP 验证码。
- 输入或粘贴 Base32 密钥，系统即时校验有效性并生成当前动态口令。
- 界面展示动态倒计时（30 秒步长周期），到期自动平滑计算并刷新下一期数字。
- 会话内自动记忆上次输入的密钥，方便连续使用。

### 回收站与安全删除（Recycle Bin）

为彻底杜绝误删风险，主界面删除条目时引入了回收站保护机制：

- **移至回收站**：主界面删除或批量删除条目时，条目记录精确删除时间（`deleted_at`），安全转入回收站并加密落盘。
- **右下角入口与计数**：主界面右下角提供直观的「回收站」按钮，并带有当前条目数角标（如 `回收站 (3)`）。
- **独立回收站面板**：
  - 支持按名称、用户名、网址即时搜索过滤已删除条目。
  - **恢复（Restore）**：无损精准恢复选中条目回到主列表，与当前最新数据互不干扰。
  - **彻底删除（Delete Permanently）**：二次确认后物理销毁选中的单条/多条条目。
  - **清空回收站（Empty Trash）**：一键彻底物理抹除所有已废弃凭据。

### 单条目密码修改历史（Password History）

每个条目修改密码时，系统自动在条目内部追加一条历史记录：

- 记录被修改的旧密码及修改时间。
- 单条目最多保留最近 10 次历史记录。
- 双击编辑条目即可查看并一键复制历史密码，防止误改误丢。

### 安全原子保存与错误恢复

为了保证密码库在跨设备网盘同步（OneDrive/iCloud/Dropbox/Syncthing）时的稳定性与断电安全性，程序采用**原地原子保存**：

1. 文件名称和完整路径在任何时候都保持恒定（如 `KeyGuard.kgvault`），不会在关闭时被重命名，避免云盘冲突或快捷方式失效。
2. 保存事务流程：
   - 先将密文写入同目录临时文件 `path.tmp`。
   - 刷新磁盘硬件缓冲区（`fsync`）。
   - 重新从磁盘读取临时文件并在内存中模拟解密验证，确保数据未损坏且能正常解密。
   - 调用系统级底层 `os.replace` 原地原子替换正式文件。
3. 意外保护：
   - 若写入过程中断电或系统崩溃，原有正式文件毫发无损。
   - 若出现异常，临时内容尽可能保留为 `.recovery` 灾备文件。
   - 错误日志默认写入 `%LOCALAPPDATA%\KeyGuard\logs\keyguard.log`，只记录操作阶段与异常信息，绝不记录明文凭据或密钥。

## 修改主密码

修改主密码时，程序会：

1. 使用当前 KDF 参数验证旧主密码。
2. 生成全新 16 字节随机盐值与 Argon2id 派生密钥。
3. 同时使用新密钥重新加密所有活动条目、用户偏好及回收站条目。
4. 只有完整写入并校验成功后，内存中才正式切换到新密钥。
5. 任一步骤失败时，原有主密码与原保险库继续保持不变。

## 保险库格式（v3）

`.kgvault` 是一个 JSON 容器。KDF 元数据和密文位于外层，条目、偏好设置和回收站位于 Fernet 加密载荷内。

```json
{
  "magic": "KGVLT",
  "version": 3,
  "kdf": {
    "algorithm": "argon2id",
    "salt": "<hex>",
    "params": {
      "time_cost": 3,
      "memory_cost_kib": 65536,
      "parallelism": 2
    }
  },
  "data": "<hex of Fernet-encrypted payload>"
}
```

密文解密后得到的 JSON 载荷包含：

```json
{
  "entries": [
    {
      "id": "<uuid4 hex>",
      "name": "...",
      "url": "...",
      "username": "...",
      "password": "...",
      "category": "website|email|social|bank|other",
      "notes": "...",
      "password_history": [
        {"password": "...", "date": "2026-11-08 10:00:00"}
      ]
    }
  ],
  "preferences": {
    "language": "zh|en",
    "auto_lock_minutes": 0,
    "column_widths": [80, 100, 80, 80, 60, 80]
  },
  "trash": [
    {
      "id": "<uuid4 hex>",
      "name": "...",
      "url": "...",
      "username": "...",
      "password": "...",
      "category": "...",
      "notes": "...",
      "password_history": [],
      "deleted_at": "2026-11-08 10:30:00"
    }
  ]
}
```

兼容性说明：

- v3 格式支持自动迁移旧版 PBKDF2 `passwords.json`。
- 迁移时自动为缺少 `id` 的条目补全 UUID，并升级为 Argon2id 密码学保护。

## 安全设计

- **KDF**：Argon2id，默认 `time_cost=3`、`memory=64 MiB`、`parallelism=2`
- **随机盐**：每个保险库独立生成 16 字节高熵盐值
- **对称加密**：Fernet（AES-128-CBC + HMAC-SHA256）
- **密钥比较**：恒定时间比较 `secrets.compare_digest` 防范计时攻击
- **原子持久化**：同目录临时文件、磁盘同步、自检解密验证、系统级原子替换
- **内存安全**：锁定或超时自动清空剪贴板与内存敏感编辑状态

> Markdown、CSV 和 JSON 导出文件包含明文密码。导出后应妥善保管，并在不再需要时安全删除。

## Windows 文件关联

打包后的程序可在“设置”中关联或取消关联 `.kgvault`：

- 注册位置为当前用户 `HKCU`，不需要管理员权限。
- 关联后双击 `.kgvault` 会调用当前 KeyGuard EXE。
- 源码运行模式下不提供文件关联。

## 测试

安装 pytest 后运行：

```powershell
python -m pytest -v
```

当前 57 项自动化测试全覆盖加密算法、KDF 派生、TOTP 动态计算、保险库安全持久化、格式迁移、回收站软删除与恢复、条目最后修改时间戳、列宽自适应布局及错误容灾等关键链路。

## 打包

安装 PyInstaller 后执行：

```powershell
python -m PyInstaller --noconfirm --clean KeyGuard.spec
```

产物位置：

```text
dist\KeyGuard.exe
```

打包配置：

- 单文件独立 EXE（免安装便携式）
- 无控制台黑框窗口
- 内嵌高精度应用图标 `icon.ico`
- 使用 `version_info.txt` 写入应用版权与版本元数据

## 项目文件

- `main.py`：主窗口界面、自适应表格、按键调度与生命周期管理
- `dialogs.py`：条目编辑、认证、设置、2FA 验证器、回收站面板等交互对话框
- `storage.py`：v3 保险库加解密、原子持久化、回收站存储规范与迁移
- `crypto_utils.py`：Argon2id/PBKDF2、RFC 6238 TOTP 计算与密码强度评估
- `i18n.py`：中英文双语语言包与即时切换
- `tests/`：pytest 自动化单元与集成测试集
- `KeyGuard.spec`：PyInstaller 打包配置规格
- `version_info.txt`：Windows 版本与版权信息定义
- `icon.ico`：应用图标

## 版权

Copyright © 2026 thriller1982. All rights reserved.
