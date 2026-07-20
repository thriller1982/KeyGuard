# KeyGuard v2.0.0

KeyGuard 是一个基于 Python 和 PySide6 的便携式本地密码管理器。

> **一个 KeyGuard EXE、一个加密的 `.kgvault` 文件和主密码，即可读取完整密码库。**

保险库是自包含文件：条目、偏好设置、KDF 参数、盐值及最多 10 份历史快照都保存在同一个 `.kgvault` 中，适合放在 U 盘、移动硬盘或个人备份位置使用。程序不依赖在线账户或远程服务。

## 当前版本

- 产品版本：`2.0.0`
- 文件版本：`2.0.0`
- 产品名称：`KeyGuard`
- 版权：`Copyright © 2026 thriller1982. All rights reserved.`

Windows 版本资源由 `version_info.txt` 提供，并通过 `KeyGuard.spec` 写入打包后的 EXE。

## 功能

- 新建或打开独立的 `.kgvault` 加密保险库
- 保存名称、网址、用户名、密码、分类和备注
- 搜索及按分类筛选条目
- 密码生成器与密码强度提示
- 密码修改历史，每个条目最多保留 10 条旧密码
- Markdown、CSV、JSON 导入与导出
- 中英文界面
- 可配置自动锁定时间
- 最多 10 份内部历史快照及只读版本切换
- 最新版相对最近历史版本的字段级“变化”提示
- 修改主密码时同步重新加密当前数据和全部历史快照
- Windows `.kgvault` 文件关联（仅打包后的 EXE）
- 原子保存、恢复文件及本地错误日志

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
2. 检测到旧版 `passwords.json` 时，提示输入原主密码并迁移到 v3 `.kgvault`。
3. 扫描 EXE 或源码所在目录：
   - 恰好存在一个有效 `.kgvault` 时，直接进入解锁流程。
   - 没有或存在多个保险库时，显示“新建/打开”选择器。

新建保险库时，默认路径为程序所在目录下的 `KeyGuard.kgvault`，用户可以选择其他位置。

## 日常保存与历史版本

### 最新版

新增、编辑、删除条目以及保存设置时，最新版会立即加密写入当前 `.kgvault` 文件。写入时保留已有历史快照。

最新版的“变化”列动态对比最近一份历史快照：

- 显示 `name`、`url`、`username`、`password`、`category`、`notes` 的变化。
- 多次编辑会累计显示相对历史基线的差异。
- 字段恢复为历史值后，对应变化提示消失。
- `password_history`、新增条目和已删除条目不显示字段变化。

### 关闭时快照

关闭程序时会比较当前完整内容与最近快照：

- 有实际变化：创建新快照，最多保留最近 10 份。
- 没有实际变化：不创建重复快照，也不消耗历史版本额度。
- 正在查看历史版本时关闭：仍以缓存中的最新版作为保存对象，不会用历史内容覆盖最新版。

历史版本通过版本下拉框切换：

- “最新版”可正常增删改。
- 历史快照只读。
- 切回“最新版”后恢复切换前的最新版内容。

## 安全保存、文件命名与恢复

当关闭时产生了新版本，程序生成：

```text
KeyGuard_<YYYYMMDD_HHMMSS>.kgvault
```

保存事务依次执行：

1. 在目标文件旁写入临时文件。
2. 刷新磁盘缓冲区。
3. 重新读取并验证容器，确认当前数据可用现有密钥解密。
4. 使用原子替换生成正式文件。
5. 仅删除本次明确打开的上一个受管 `KeyGuard.kgvault` 或 `KeyGuard_<时间>.kgvault`。

程序不会通配删除同目录中的其他保险库或用户自行命名的备份。

关键保存步骤失败时：

- 原保险库保持不变。
- 临时内容尽可能保留为 `.recovery` 文件。
- 显示原文件、恢复文件、具体错误和日志路径。
- 调用关闭阻止逻辑，让 KeyGuard 保持打开。

如果新文件已经安全写入，只是旧受管文件无法删除，程序会保留新旧两个文件、显示警告并允许退出。

错误日志默认位置：

```text
%LOCALAPPDATA%\KeyGuard\logs\keyguard.log
```

日志只记录时间、操作阶段、异常类型及相关文件路径，不记录主密码、派生密钥或保险库明文。

## 修改主密码

修改主密码时，程序会：

1. 使用保险库当前记录的 KDF 类型和参数验证旧密码。
2. 生成新的随机盐和 Argon2id 密钥。
3. 使用旧密钥解密全部历史快照，再使用新密钥重新加密。
4. 使用新密钥保存当前数据和全部历史快照。
5. 只有完整写入成功后才在内存中切换到新密钥。

任一步骤失败时，原主密码、原密钥、原保险库及原快照继续有效。

## 保险库格式（v3）

`.kgvault` 是一个 JSON 容器。KDF 元数据和密文位于外层，条目与偏好设置位于 Fernet 加密载荷内。

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
  "data": "<hex of Fernet-encrypted current payload>",
  "snapshots": [
    {
      "timestamp": "2026-07-20 19:00:00",
      "data": "<hex of Fernet-encrypted snapshot payload>",
      "change": {"<entry_id>": ["name", "url"]}
    }
  ]
}
```

当前数据和每份快照解密后均包含：

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
        {"password": "...", "date": "2026-07-20 19:00:00"}
      ]
    }
  ],
  "preferences": {
    "language": "zh|en",
    "auto_lock_minutes": 0,
    "column_widths": []
  }
}
```

兼容性说明：

- v3 不直接打开旧的 v2 `.kgvault`。
- 旧版 PBKDF2 `passwords.json` 可以自动迁移。
- 迁移时为缺少 `id` 的条目生成 UUID，并使用 Argon2id 重新加密。

## 安全设计

- KDF：Argon2id，默认 `time_cost=3`、`memory=64 MiB`、`parallelism=2`
- 随机盐：每个保险库独立生成 16 字节盐值
- 对称加密：Fernet（AES-128-CBC + HMAC-SHA256）
- 旧格式迁移：PBKDF2-SHA256 600,000 次迭代解密后转为 Argon2id
- 密钥比较：使用 `secrets.compare_digest`
- 保存方式：同目录临时文件、磁盘刷新、解密验证、原子替换
- 主密码轮换：当前数据与所有快照整体换密钥

> Markdown、CSV 和 JSON 导出文件包含明文密码。导出后应妥善保管，并在不再需要时安全删除。

## Windows 文件关联

打包后的程序可在“设置”中关联或取消关联 `.kgvault`：

- 注册位置为当前用户 `HKCU`，不需要管理员权限。
- 关联后双击 `.kgvault` 会调用当前 KeyGuard EXE。
- 源码运行模式下不提供文件关联。

## 测试

安装 pytest 后运行：

```powershell
python -m pytest -q
```

当前测试覆盖加密、KDF、保险库读写、迁移、快照轮换、动态变化、主密码换密钥、安全关闭、日志和精确文件清理等关键路径。

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

- 单文件 EXE
- 无控制台窗口
- 使用 `icon.ico`
- 使用 `version_info.txt` 写入 v2.0.0 和版权信息

## 项目文件

- `main.py`：主窗口、保存流程、版本切换和启动逻辑
- `dialogs.py`：条目、认证、主密码、设置、生成器等对话框
- `storage.py`：v3 保险库、快照、迁移、安全写入、恢复日志和文件关联
- `crypto_utils.py`：Argon2id/PBKDF2、密码强度和加密辅助逻辑
- `i18n.py`：中英文界面文本
- `tests/`：pytest 测试
- `KeyGuard.spec`：PyInstaller 打包配置
- `version_info.txt`：Windows 版本与版权资源
- `icon.ico`：应用图标

## 版权

Copyright © 2026 thriller1982. All rights reserved.
