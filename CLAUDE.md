# 密码管理器 (Recovered Project)

从 `密码管理软件.exe` 反向恢复的 Python 项目。

## 技术栈

- Python 3.14
- PySide6 (GUI)
- cryptography (加密)

## 命令

```bash
# 安装依赖
pip install -r requirements.txt

# 运行应用
python main.py

# 运行测试
pytest

# 打包 (需要 PyInstaller)
pyinstaller 密码管理器.spec
```

## 项目结构

```
├── main.py          # 主窗口与应用启动逻辑
├── dialogs.py       # 各类对话框 (Auth, Entry, Settings, LockScreen 等)
├── storage.py       # 配置、加密数据存储、备份恢复
├── crypto_utils.py  # 密钥派生 (PBKDF2)、加密 (Fernet)、密码强度评估
├── i18n.py          # 中英文文案
├── config.json      # 默认配置模板
├── passwords.json   # 默认密码数据模板
├── icon.ico         # 应用图标
├── 密码管理器.spec   # PyInstaller 打包配置
├── tests/           # 测试目录
│   ├── test_crypto_utils.py
│   └── test_storage.py
├── data/            # 运行时数据 (首次启动自动创建)
│   ├── config.json
│   ├── passwords.json
│   └── backups/
├── build/           # 打包中间产物
└── dist/            # 打包输出
```

## 数据格式

密码数据文件 (`data/passwords.json`):
```json
{
  "salt": "<hex>",
  "data": "<hex>"
}
```

解密后为条目列表，每个条目包含: `name`, `url`, `username`, `password`, `notes`, `category`, `password_history`

## 关键常量

- `CLIPBOARD_CLEAR_MS = 300000` (剪贴板自动清除时间 5 分钟)
- `PASSWORD_HISTORY_LIMIT = 10` (密码历史记录上限)

## 注意事项

- **恢复项目**: 这是从 Python 3.14 字节码手工恢复的，非原始源码
- **数据迁移**: 首次启动会自动将根目录的旧版 `config.json`、`passwords.json` 迁移到 `data/`
- **主密码**: 首次启动需设置主密码，会创建 `data/passwords.json` 和 `data/config.json`
- **备份**: 默认备份目录 `data/backups/`
- **GUI 差异**: 部分界面细节、提示时机、锁屏交互可能与原版 exe 有细微差异
- **测试覆盖**: 仅核心存储与加密流程有最小测试集

## 语言

始终使用中文回复。
