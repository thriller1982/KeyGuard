# Recovered Password Manager

这是从 `密码管理软件.exe` 中恢复出来的开发项目版本。

## Files

- `main.py`: 主窗口与应用启动逻辑
- `dialogs.py`: 各类对话框
- `storage.py`: 配置、加密数据存储、备份恢复
- `crypto_utils.py`: 密钥派生、加密和密码强度评估
- `i18n.py`: 中英文文案
- `icon.ico`: 应用图标

## Requirements

安装依赖：

```bash
pip install -r requirements.txt
```

## Run

```bash
python main.py
```

## Test

安装 `pytest` 后可运行：

```bash
pytest
```

## First Launch

首次启动会要求你设置并确认主密码。

- 会创建 `data/passwords.json`
- 会创建 `data/config.json`
- 备份文件默认放在 `data/backups/`

运行数据默认位于项目下的 `data/` 目录。
如果项目根目录已经存在旧版 `config.json`、`passwords.json` 或 `backups/`，程序会在启动时自动迁移到 `data/` 目录。

## Data Format

密码数据文件大致格式：

```json
{
  "salt": "<hex>",
  "data": "<hex>"
}
```

解密后是条目列表，每个条目通常包含：

- `name`
- `url`
- `username`
- `password`
- `notes`
- `category`
- `password_history`

## Notes

这是根据 `Python 3.14` 字节码手工恢复的项目，不是原始源码直出。

当前版本特点：

- 核心加密/存储逻辑恢复度高
- GUI 和交互流程基本完整
- 少数界面细节、提示时机、锁屏交互可能与原版存在细微差异
- 已将运行数据与源码目录分离，并补充了首次主密码确认
- 已补充核心存储与加密流程的最小测试集

## Known Differences

- `LockScreen` 的密码校验主要由主窗口流程控制
- 个别对话框的刷新细节可能与原版不完全一致
- 如果需要重新打包，建议先手动完整测试所有功能
