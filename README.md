# 🎮 Hollow Knight Save Editor

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Hollow Knight](https://img.shields.io/badge/game-Hollow%20Knight-orange.svg)](https://www.hollowknight.com/)

> 一个功能强大的空洞骑士存档修改器，支持命令行、图形界面和Web界面三种模式。

---


### ✨ 功能特性

- 🔓 **解密/加密** - 支持空洞骑士 `.dat` 存档文件的完整解析和重新打包
- 🎨 **三种界面** - CLI交互式、GUI图形界面、Web网页界面随心切换
- ⚡ **一键满配** - 瞬间获得满级装备、全技能、全护符
- 🎯 **精细修改** - 支持吉欧、血量、骨钉、法术等数十项数据调整
- 💾 **自动备份** - 修改前自动导出JSON备份，安全无忧
- 🐛 **幼虫救援** - 一键解救全部46只幼虫
- 🏆 **完成度调整** - 直接设置112%完成度解锁真结局

### 📋 系统要求

- **Python**: 3.8 或更高版本
- **操作系统**: Windows / macOS / Linux
- **游戏版本**: 支持空洞骑士 v1.4.3.2+（包括丝之歌发售前的最新版本）

---

```bash
# 克隆仓库
git clone https://github.com/yourusername/hollow-knight-save-editor.git
cd hollow-knight-save-editor

# 安装依赖
pip install -r requirements.txt
```

# 📖 使用指南
- ### Web界面模式
```
python hk.py --web              # 默认启动在 http://127.0.0.1:5000
python hk.py --web --port 8080  # 自定义端口
python hk.py --web --host 0.0.0.0 # 允许局域网访问
```
启动后自动打开浏览器，拖拽或选择存档文件即可开始编辑。

- ### GUI图形界面
```
python hk.py --gui
python hk.py --gui path/to/user1.dat  # 直接加载指定存档
```
- ### CLI命令行模式


#### 交互式编辑
`python hk.py user1.dat`

#### 快速修改预设
```
python hk.py user1.dat --preset max     # 一键满配
python hk.py user1.dat --preset geo     # 仅满金钱
python hk.py user1.dat --preset health  # 仅满血量
python hk.py user1.dat --preset skills  # 仅解锁全技能
```
