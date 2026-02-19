#!/usr/bin/env python3
"""
Hollow Knight Save Editor - 交互式存档修改器
支持命令行交互、GUI图形界面和Web界面
"""

import json
import base64
import os
import sys
import argparse
import webbrowser
import threading
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Callable, Optional, Any, Tuple, Union

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("请先安装依赖: pip install cryptography")
    sys.exit(1)


class SaveParser:
    STRING_TOKEN = 0x06
    SAVE_KEY = b"UKu52ePUBwetZ9wNX88o54dnfKRu0T1l"

    def __init__(self):
        self.backend = default_backend()

    def parse_dat_file(self, file_path: str | Path) -> dict:
        file_path = Path(file_path)
        with open(file_path, 'rb') as f:
            raw = f.read()

        extraction = self._extract_string(raw)
        json_text = self._decrypt_base64(extraction['base64'])

        return {
            'json': json.loads(json_text),
            'meta': extraction['meta'],
            'original_name': file_path.stem
        }

    def export_dat_file(self, json_data: dict, meta: dict, output_path: str | Path = None) -> bytes:
        json_text = json.dumps(json_data, separators=(',', ':'))
        base64_str = self._encrypt_json(json_text)
        new_length_bytes = self._write_7bit_encoded_int(len(base64_str))
        new_string_bytes = base64_str.encode('utf-8')

        result = meta['header'] + new_length_bytes + new_string_bytes + meta['footer']

        if output_path:
            Path(output_path).write_bytes(result)

        return result

    def _extract_string(self, raw: bytes) -> dict:
        for i in range(len(raw)):
            if raw[i] == self.STRING_TOKEN:
                strlen_offset = i + 5
                length, string_start = self._read_7bit_encoded_int(raw, strlen_offset)
                utf8_bytes = raw[string_start:string_start + length]
                base64_str = utf8_bytes.decode('utf-8')

                return {
                    'base64': base64_str,
                    'meta': {
                        'header': raw[:strlen_offset],
                        'footer': raw[string_start + length:]
                    }
                }
        raise ValueError("未找到 BinaryFormatter 字符串对象 (0x06 标记)")

    def _read_7bit_encoded_int(self, raw: bytes, pos: int) -> tuple:
        result = 0
        shift = 0
        offset = pos

        while True:
            b = raw[offset]
            offset += 1
            result |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                break
            shift += 7

        return result, offset

    def _write_7bit_encoded_int(self, value: int) -> bytes:
        bytes_list = []
        v = value
        while v >= 0x80:
            bytes_list.append((v | 0x80) & 0xFF)
            v >>= 7
        bytes_list.append(v)
        return bytes(bytes_list)

    def _decrypt_base64(self, base64_str: str) -> str:
        encrypted = base64.b64decode(base64_str)
        cipher = Cipher(algorithms.AES(self.SAVE_KEY), modes.ECB(), backend=self.backend)
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
        return decrypted.decode('utf-8')

    def _encrypt_json(self, json_text: str) -> str:
        data = json_text.encode('utf-8')
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        cipher = Cipher(algorithms.AES(self.SAVE_KEY), modes.ECB(), backend=self.backend)
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(encrypted).decode('utf-8')


class SaveEditorCore:
    """核心编辑功能（CLI、GUI和Web共用）"""

    def __init__(self):
        self.parser = SaveParser()
        self.script_dir = Path(__file__).parent.absolute()
        self.output_dir = self.script_dir / "outputs"
        self.output_dir.mkdir(exist_ok=True)

        # 定义所有可修改的项目
        self.categories = self._build_categories()

    def _build_categories(self) -> Dict:
        return {
            "1": {
                "name": "💰 资源与货币",
                "items": [
                    {"id": "geo", "name": "吉欧 (Geo)", "field": "geo", "type": "int", "max": 999999, "default": 99999, "desc": "游戏货币"},
                    {"id": "ore", "name": "苍白矿石", "field": "ore", "type": "int", "max": 6, "default": 6, "desc": "升级骨钉材料"},
                    {"id": "rancidEggs", "name": "腐臭蛋", "field": "rancidEggs", "type": "int", "max": 20, "default": 20, "desc": "找回阴影道具"},
                    {"id": "simpleKeys", "name": "简单钥匙", "field": "simpleKeys", "type": "int", "max": 3, "default": 3, "desc": "开启简单锁"},
                ]
            },
            "2": {
                "name": "❤️ 生命值与灵魂",
                "items": [
                    {"id": "maxHealth", "name": "最大血量", "field": "maxHealth", "type": "int", "max": 9, "default": 9, "desc": "面具数量(9=满级)", "related": ["health", "maxHealthBase"]},
                    {"id": "heartPieces", "name": "生命碎片", "field": "heartPieces", "type": "int", "max": 4, "default": 4, "desc": "4个=1格血"},
                    {"id": "vesselFragments", "name": "容器碎片", "field": "vesselFragments", "type": "int", "max": 3, "default": 3, "desc": "3个=1灵魂容器", "related": ["MPReserve", "MPReserveMax"]},
                ]
            },
            "3": {
                "name": "⚔️ 骨钉与伤害",
                "items": [
                    {"id": "nailSmithUpgrades", "name": "骨钉升级", "field": "nailSmithUpgrades", "type": "int", "max": 4, "default": 4, "desc": "0-4级(4=纯粹骨钉)", "related": ["honedNail"]},
                    {"id": "nailDamage", "name": "骨钉伤害", "field": "nailDamage", "type": "int", "max": 21, "default": 21, "desc": "基础伤害值"},
                ]
            },
            "4": {
                "name": "🏃 移动技能",
                "items": [
                    {"id": "hasDash", "name": "冲刺", "field": "hasDash", "type": "bool", "default": True, "desc": "蛾翼披风", "related": ["canDash"]},
                    {"id": "hasShadowDash", "name": "暗影冲刺", "field": "hasShadowDash", "type": "bool", "default": True, "desc": "升级冲刺", "related": ["canShadowDash"]},
                    {"id": "hasWalljump", "name": "爬墙", "field": "hasWalljump", "type": "bool", "default": True, "desc": "螳螂爪", "related": ["canWallJump"]},
                    {"id": "hasDoubleJump", "name": "二段跳", "field": "hasDoubleJump", "type": "bool", "default": True, "desc": "帝王之翼"},
                    {"id": "hasSuperDash", "name": "超级冲刺", "field": "hasSuperDash", "type": "bool", "default": True, "desc": "水晶之心", "related": ["canSuperDash"]},
                    {"id": "hasAcidArmour", "name": "酸泳", "field": "hasAcidArmour", "type": "bool", "default": True, "desc": "伊思玛的眼泪"},
                ]
            },
            "5": {
                "name": "✨ 法术与能力",
                "items": [
                    {"id": "fireballLevel", "name": "复仇之魂", "field": "fireballLevel", "type": "int", "max": 2, "default": 2, "desc": "0=无,1=白波,2=黑波", "related": ["hasSpell"]},
                    {"id": "quakeLevel", "name": "荒芜俯冲", "field": "quakeLevel", "type": "int", "max": 2, "default": 2, "desc": "0=无,1=白砸,2=黑砸"},
                    {"id": "screamLevel", "name": "嚎叫幽灵", "field": "screamLevel", "type": "int", "max": 2, "default": 2, "desc": "0=无,1=白吼,2=黑吼"},
                    {"id": "hasDreamNail", "name": "梦之钉", "field": "hasDreamNail", "type": "bool", "default": True, "desc": "收集精华"},
                    {"id": "dreamNailUpgraded", "name": "觉醒梦之钉", "field": "dreamNailUpgraded", "type": "bool", "default": True, "desc": "升级梦之钉"},
                    {"id": "hasDreamGate", "name": "梦之门", "field": "hasDreamGate", "type": "bool", "default": True, "desc": "设置传送点"},
                ]
            },
            "6": {
                "name": "🔑 关键道具",
                "items": [
                    {"id": "hasLantern", "name": "光蝇灯笼", "field": "hasLantern", "type": "bool", "default": True, "desc": "照亮黑暗"},
                    {"id": "hasCityKey", "name": "城市纹章", "field": "hasCityKey", "type": "bool", "default": True, "desc": "泪水之城主门"},
                    {"id": "hasTramPass", "name": "电车票", "field": "hasTramPass", "type": "bool", "default": True, "desc": "电车系统"},
                    {"id": "hasKingsBrand", "name": "国王印记", "field": "hasKingsBrand", "type": "bool", "default": True, "desc": "深渊通行证"},
                    {"id": "hasLoveKey", "name": "爱之钥匙", "field": "hasLoveKey", "type": "bool", "default": True, "desc": "爱之塔"},
                    {"id": "hasSlykey", "name": "店主的钥匙", "field": "hasSlykey", "type": "bool", "default": True, "desc": "斯莱额外商品"},
                ]
            },
            "7": {
                "name": "🐛 幼虫收集",
                "items": [
                    {"id": "grubsCollected", "name": "已救幼虫", "field": "grubsCollected", "type": "int", "max": 46, "default": 46, "desc": "总共46只", "related": ["grubRewards"]},
                ]
            },
            "8": {
                "name": "🎭 护符相关",
                "items": [
                    {"id": "charmSlots", "name": "护符槽", "field": "charmSlots", "type": "int", "max": 11, "default": 11, "desc": "最大11个"},
                    {"id": "_unlockAllCharms", "name": "⭐ 解锁所有护符", "field": "_special", "type": "special", "action": "unlock_all_charms", "desc": "获得全部40个护符"},
                    {"id": "_unlockAllNotches", "name": "⭐ 解锁所有护符槽", "field": "_special", "type": "special", "action": "unlock_all_notches", "desc": "获得全部护符槽升级"},
                ]
            },
            "9": {
                "name": "📖 猎人日志",
                "items": [
                    {"id": "hasJournal", "name": "猎人日志", "field": "hasJournal", "type": "bool", "default": True, "desc": "获得日志"},
                    {"id": "_completeJournal", "name": "⭐ 完成所有条目", "field": "_special", "type": "special", "action": "complete_journal", "desc": "标记所有敌人已击败"},
                    {"id": "hasHuntersMark", "name": "猎人印记", "field": "hasHuntersMark", "type": "bool", "default": True, "desc": "击败所有类型敌人"},
                ]
            },
            "10": {
                "name": "🏆 完成度与统计",
                "items": [
                    {"id": "completionPercentage", "name": "完成度", "field": "completionPercentage", "type": "float", "max": 112.0, "default": 112.0, "desc": "112%为真结局"},
                    {"id": "unlockedCompletionRate", "name": "显示112%", "field": "unlockedCompletionRate", "type": "bool", "default": True, "desc": "可查看超100%"},
                ]
            },
        }

    def apply_special_action(self, data: dict, action: str) -> str:
        """应用特殊操作"""
        if action == "unlock_all_charms":
            for i in range(1, 41):
                data[f'gotCharm_{i}'] = True
                data[f'equippedCharm_{i}'] = False
            return "已解锁全部40个护符"

        elif action == "unlock_all_notches":
            data['charmSlots'] = 11
            data['notchShroomOgres'] = True
            data['notchFogCanyon'] = True
            data['salubraNotch1'] = True
            data['salubraNotch2'] = True
            data['salubraNotch3'] = True
            data['salubraNotch4'] = True
            data['slyNotch1'] = True
            data['slyNotch2'] = True
            data['gotGrimmNotch'] = True
            return "已解锁全部11个护符槽"

        elif action == "complete_journal":
            data['journalEntriesCompleted'] = 146
            data['journalNotesCompleted'] = 146
            data['hasHuntersMark'] = True
            for key in list(data.keys()):
                if key.startswith('killed') and not key.startswith('kills'):
                    data[key] = True
            return "已完成猎人日志"

        elif action == "max_everything":
            # 资源
            data['geo'] = 99999
            data['ore'] = 6
            data['rancidEggs'] = 20
            data['simpleKeys'] = 3

            # 血量
            data['maxHealth'] = 9
            data['health'] = 9
            data['maxHealthBase'] = 9
            data['heartPieces'] = 4
            data['vesselFragments'] = 3
            data['MPReserve'] = 99
            data['MPReserveMax'] = 99

            # 骨钉
            data['nailSmithUpgrades'] = 4
            data['nailDamage'] = 21
            data['honedNail'] = True

            # 技能
            for skill in ['hasDash', 'hasShadowDash', 'hasWalljump', 'hasDoubleJump',
                         'hasSuperDash', 'hasAcidArmour', 'canDash', 'canWallJump',
                         'canSuperDash', 'canShadowDash']:
                data[skill] = True

            # 法术
            data['fireballLevel'] = 2
            data['quakeLevel'] = 2
            data['screamLevel'] = 2
            data['hasSpell'] = True
            data['hasDreamNail'] = True
            data['dreamNailUpgraded'] = True
            data['hasDreamGate'] = True

            # 道具
            for item in ['hasLantern', 'hasCityKey', 'hasTramPass', 'hasKingsBrand',
                        'hasLoveKey', 'hasSlykey', 'hasQuill']:
                data[item] = True

            # 幼虫
            data['grubsCollected'] = 46
            data['grubRewards'] = 46

            # 护符和日志
            self.apply_special_action(data, "unlock_all_charms")
            self.apply_special_action(data, "unlock_all_notches")
            self.apply_special_action(data, "complete_journal")

            # 完成度
            data['completionPercentage'] = 112.0
            data['unlockedCompletionRate'] = True

            return "一键满配完成！"

        return "未知操作"

    def apply_modification(self, data: dict, item: dict, value: Any) -> str:
        """应用单个修改"""
        field_type = item['type']

        if field_type == 'special':
            return self.apply_special_action(data, item['action'])

        field = item['field']
        data[field] = value

        # 处理关联字段
        if 'related' in item:
            for related in item['related']:
                if field_type == 'bool':
                    data[related] = value
                elif field == 'maxHealth':
                    if related == 'health':
                        data[related] = value
                    elif related == 'maxHealthBase':
                        data[related] = value
                elif field == 'nailSmithUpgrades' and related == 'honedNail' and value >= 1:
                    data[related] = True
                elif field == 'grubsCollected' and related == 'grubRewards':
                    data[related] = value

        return f"{item['name']} = {value}"

    def save_files(self, data: dict, meta: dict, original_name: str) -> Tuple[Path, Path]:
        """保存修改后的文件"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M")

        json_path = self.output_dir / f"{original_name}_{timestamp}.json"
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

        dat_path = self.output_dir / f"{original_name}_{timestamp}_modified.dat"
        self.parser.export_dat_file(data, meta, dat_path)

        return json_path, dat_path


class CLIEditor(SaveEditorCore):
    """命令行交互版本"""

    def interactive_edit(self, input_file: str):
        """交互式编辑"""
        input_path = Path(input_file)
        if not input_path.exists():
            print(f"❌ 文件不存在: {input_file}")
            return False

        print(f"\n📂 正在解析存档: {input_file}")
        try:
            result = self.parser.parse_dat_file(input_path)
            data = result['json']
            meta = result['meta']
            original_name = result['original_name']
        except Exception as e:
            print(f"❌ 解析失败: {e}")
            return False

        # 处理 playerData 嵌套结构
        if 'playerData' in data:
            player_data = data['playerData']
            merged_data = {**data, **player_data}
            self.original_structure = data
            data = merged_data
        else:
            self.original_structure = None

        modifications = []
        modified = False

        while True:
            self._display_menu()
            choice = input("请输入选项: ").strip().lower()

            if choice == 'q':
                if modified:
                    confirm = input("有未保存的修改，确定要放弃吗？(y/n): ").strip().lower()
                    if confirm != 'y':
                        continue
                print("已放弃修改")
                return False

            elif choice == 's':
                if not modified:
                    confirm = input("尚未做任何修改，确定要保存吗？(y/n): ").strip().lower()
                    if confirm != 'y':
                        continue

                save_data = data
                if self.original_structure and 'playerData' in self.original_structure:
                    for key in self.original_structure['playerData'].keys():
                        if key in data:
                            self.original_structure['playerData'][key] = data[key]
                    for key in ['geo', 'nailSmithUpgrades', 'completionPercentage']:
                        if key in data:
                            self.original_structure[key] = data[key]
                    save_data = self.original_structure

                json_path, dat_path = self.save_files(save_data, meta, original_name)

                print(f"\n{'='*60}")
                print("✅ 修改完成！文件已保存:")
                print(f"   📄 JSON: {json_path}")
                print(f"   🎮 DAT:  {dat_path}")
                print(f"{'='*60}")

                if modifications:
                    print("\n📋 修改记录:")
                    for mod in modifications:
                        print(f"   • {mod}")

                return True

            elif choice == 'r':
                if not modified:
                    print("当前没有修改需要重置")
                    continue
                confirm = input("确定要重置所有修改吗？(y/n): ").strip().lower()
                if confirm == 'y':
                    result = self.parser.parse_dat_file(input_path)
                    data = result['json']
                    meta = result['meta']
                    if 'playerData' in data:
                        self.original_structure = data
                        data = {**data, **data['playerData']}
                    else:
                        self.original_structure = None
                    modifications = []
                    modified = False
                    print("✅ 已重置为原始存档")

            elif choice == '0':
                print("\n⚡ 一键满配 - 将所有数值设为最大值")
                confirm = input("确定执行一键满配吗？(y/n): ").strip().lower()
                if confirm == 'y':
                    result = self.apply_special_action(data, 'max_everything')
                    modifications.append(f"⚡ {result}")
                    modified = True
                    print(f"✅ {result}")
                    input("按回车继续...")

            elif choice in self.categories:
                mods = self._edit_category(data, self.categories[choice])
                if mods:
                    modifications.extend(mods)
                    modified = True

            else:
                print("❌ 无效的选项")
                input("按回车继续...")

    def _display_menu(self):
        print("\n" + "="*60)
        print("🎮 空洞骑士存档修改器 - Hollow Knight Save Editor")
        print("="*60)
        print(f"📁 输出目录: {self.output_dir}")
        print("-"*60)
        print("请选择要修改的分类:\n")

        for key, cat in sorted(self.categories.items(), key=lambda x: int(x[0])):
            print(f"  [{key}] {cat['name']}")

        print("\n  [0] ⚡ 一键满配")
        print("-"*60)
        print("  [s] 保存并导出存档")
        print("  [q] 放弃修改并退出")
        print("  [r] 重置所有修改")
        print("="*60)

    def _edit_category(self, data: dict, category: dict) -> List[str]:
        """编辑分类"""
        print(f"\n{'='*60}")
        print(f"📂 {category['name']}")
        print(f"{'='*60}")
        print("输入编号选择要修改的项目，直接回车返回主菜单\n")

        items = category['items']
        for i, item in enumerate(items, 1):
            field = item['field']
            current = data.get(field, "N/A")
            max_info = f" (最大: {item['max']})" if 'max' in item else ""
            print(f"  [{i}] {item['name']}{max_info}")
            print(f"      └─ {item['desc']} [当前: {current}]")
            print()

        print(f"  [0] 返回主菜单")
        print(f"{'='*60}")

        modifications = []

        while True:
            choice = input("请选择项目: ").strip()
            if choice == '0' or choice == '':
                break

            try:
                idx = int(choice) - 1
                if 0 <= idx < len(items):
                    item = items[idx]
                    value = self._get_input_value(item, data.get(item['field']))
                    result = self.apply_modification(data, item, value)
                    modifications.append(result)
                    print(f"\n✅ 已修改: {result}")
                    input("按回车继续...")
                    print(f"\n{'='*60}")
                    print(f"📂 {category['name']} (继续选择或回车返回)")
                    print(f"{'='*60}")
                else:
                    print("❌ 无效的选择")
            except ValueError:
                print("❌ 请输入数字")

        return modifications

    def _get_input_value(self, item: dict, current_val: Any) -> Any:
        """获取用户输入"""
        field_type = item['type']
        default = item.get('default')
        max_val = item.get('max')

        print(f"\n{'-'*50}")
        print(f"当前项目: {item['name']}")
        print(f"说明: {item['desc']}")
        print(f"当前值: {current_val}")
        print(f"{'-'*50}")

        if field_type == 'bool':
            val = input(f"输入 true/false (默认: {default}): ").strip().lower()
            if not val:
                return default if default is not None else current_val
            return val in ['true', 't', 'yes', 'y', '1']

        elif field_type == 'int':
            hint = f"0-{max_val}" if max_val else "任意整数"
            val = input(f"输入整数 [{hint}] (默认: {default}, 直接回车使用当前值): ").strip()
            if not val:
                return current_val if current_val is not None else default
            try:
                num = int(val)
                if max_val is not None and num > max_val:
                    print(f"⚠️ 超过最大值 {max_val}，已设为 {max_val}")
                    return max_val
                return num
            except ValueError:
                print("⚠️ 输入无效，使用当前值")
                return current_val

        elif field_type == 'float':
            hint = f"0-{max_val}" if max_val else "任意数值"
            val = input(f"输入数值 [{hint}] (默认: {default}): ").strip()
            if not val:
                return current_val if current_val is not None else default
            try:
                num = float(val)
                if max_val is not None and num > max_val:
                    print(f"⚠️ 超过最大值 {max_val}，已设为 {max_val}")
                    return max_val
                return num
            except ValueError:
                print("⚠️ 输入无效，使用当前值")
                return current_val

        elif field_type == 'special':
            print("这是一个特殊操作，将自动应用预设修改")
            input("按回车确认...")
            return item.get('default', True)

        return default

    def quick_modify(self, input_file: str, preset: str):
        """快速修改"""
        input_path = Path(input_file)
        if not input_path.exists():
            print(f"❌ 文件不存在: {input_file}")
            return False

        result = self.parser.parse_dat_file(input_path)
        data = result['json']
        meta = result['meta']
        original_name = result['original_name']

        if 'playerData' in data:
            player_data = data['playerData']
            merged_data = {**data, **player_data}
            save_data = data
            data = merged_data
        else:
            save_data = data

        if preset == 'max':
            self.apply_special_action(data, 'max_everything')
            if 'playerData' in save_data:
                for key in save_data['playerData'].keys():
                    if key in data:
                        save_data['playerData'][key] = data[key]
                for key in ['geo', 'nailSmithUpgrades', 'completionPercentage']:
                    if key in data:
                        save_data[key] = data[key]
        elif preset == 'geo':
            data['geo'] = 99999
            if 'playerData' in save_data:
                save_data['playerData']['geo'] = 99999
            save_data['geo'] = 99999
        elif preset == 'health':
            data['maxHealth'] = 9
            data['health'] = 9
            if 'playerData' in save_data:
                save_data['playerData']['maxHealth'] = 9
                save_data['playerData']['health'] = 9
        elif preset == 'skills':
            for skill in ['hasDash', 'hasShadowDash', 'hasWalljump',
                         'hasDoubleJump', 'hasSuperDash', 'hasAcidArmour']:
                data[skill] = True
                if 'playerData' in save_data:
                    save_data['playerData'][skill] = True

        json_path, dat_path = self.save_files(save_data, meta, original_name)
        print(f"✅ 快速修改完成: {dat_path}")
        return True


class GUIEditor(SaveEditorCore):
    """图形界面版本 - 修复数据读取问题"""

    def __init__(self):
        super().__init__()
        self.tk = None
        self.root = None
        self.data = None  # 实际使用的扁平化数据
        self.original_data = None  # 原始嵌套结构数据
        self.meta = None
        self.original_name = ""
        self.current_file = ""
        self.check_vars = {}
        self.entry_vars = {}  # 存储输入框的变量

    def run(self, input_file: str = None):
        """启动GUI"""
        try:
            import tkinter as tk
            from tkinter import ttk, messagebox, filedialog
            self.tk = tk
            self.ttk = ttk
            self.messagebox = messagebox
            self.filedialog = filedialog
        except ImportError:
            print("❌ 无法导入tkinter，请安装Python的GUI支持")
            print("   Ubuntu/Debian: sudo apt-get install python3-tk")
            print("   或使用CLI模式: python hk.py user1.dat")
            return False

        self.root = self.tk.Tk()
        self.root.title("🎮 空洞骑士存档修改器")
        self.root.geometry("1000x750")
        self.root.minsize(900, 600)

        self._setup_styles()
        self._create_ui()

        if input_file and Path(input_file).exists():
            self.load_file(input_file)

        self.root.mainloop()
        return True

    def _setup_styles(self):
        """设置样式"""
        style = self.ttk.Style()
        style.configure('Title.TLabel', font=('Microsoft YaHei', 16, 'bold'))
        style.configure('Category.TLabelframe', font=('Microsoft YaHei', 11, 'bold'))
        style.configure('Item.TFrame', padding=5)

    def _create_ui(self):
        """创建界面"""
        # 顶部文件选择
        top_frame = self.tk.Frame(self.root, padx=10, pady=10, bg='#f0f0f0')
        top_frame.pack(fill='x')

        self.tk.Label(top_frame, text="存档文件:", font=('Microsoft YaHei', 11), bg='#f0f0f0').pack(side='left')
        self.file_entry = self.tk.Entry(top_frame, width=50, font=('Microsoft YaHei', 10))
        self.file_entry.pack(side='left', padx=5, fill='x', expand=True)

        btn_frame = self.tk.Frame(top_frame, bg='#f0f0f0')
        btn_frame.pack(side='left')

        self.tk.Button(btn_frame, text="📂 浏览", command=self.browse_file,
                      font=('Microsoft YaHei', 10)).pack(side='left', padx=2)
        self.tk.Button(btn_frame, text="📂 加载", command=self.load_from_entry,
                      font=('Microsoft YaHei', 10), bg='#4CAF50', fg='white').pack(side='left', padx=2)

        # 信息栏
        self.info_frame = self.tk.LabelFrame(self.root, text="📊 存档信息", padx=10, pady=5,
                                            font=('Microsoft YaHei', 10, 'bold'))
        self.info_frame.pack(fill='x', padx=10, pady=5)

        self.info_text = self.tk.StringVar(value="未加载存档")
        self.tk.Label(self.info_frame, textvariable=self.info_text, font=('Microsoft YaHei', 10),
                     fg='blue').pack(anchor='w')

        # 创建笔记本（标签页）
        self.notebook = self.ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=5)

        # 为每个分类创建标签页
        self.tabs = {}
        self.category_frames = {}

        for cat_key, cat_data in sorted(self.categories.items(), key=lambda x: int(x[0])):
            tab = self.tk.Frame(self.notebook)
            self.notebook.add(tab, text=cat_data['name'])
            self.tabs[cat_key] = tab
            self._create_category_tab(tab, cat_data, cat_key)

        # 底部按钮区域
        bottom_frame = self.tk.Frame(self.root, padx=10, pady=10, bg='#e0e0e0')
        bottom_frame.pack(fill='x', side='bottom')

        # 一键操作
        quick_frame = self.tk.LabelFrame(bottom_frame, text="⚡ 快速操作", padx=5, pady=5,
                                          font=('Microsoft YaHei', 10, 'bold'))
        quick_frame.pack(fill='x', pady=5)

        quick_buttons = [
            ("🌟 一键满配", self.max_everything, '#FF6B6B'),
            ("💰 满金钱", lambda: self.quick_set('geo', 99999), '#4ECDC4'),
            ("❤️ 满血量", self.max_health, '#FF6B6B'),
            ("⚔️ 满骨钉", self.max_nail, '#95E1D3'),
            ("🏃 全技能", self.all_skills, '#F38181'),
        ]

        for text, cmd, color in quick_buttons:
            self.tk.Button(quick_frame, text=text, command=cmd,
                          bg=color, fg='white' if color != '#95E1D3' else 'black',
                          font=('Microsoft YaHei', 10, 'bold'), padx=10, pady=5).pack(side='left', padx=5)

        # 保存按钮
        save_frame = self.tk.Frame(bottom_frame, bg='#e0e0e0')
        save_frame.pack(fill='x', pady=5)

        self.save_btn = self.tk.Button(save_frame, text="💾 保存修改", command=self.save_file,
                                      bg='#4CAF50', fg='white', font=('Microsoft YaHei', 12, 'bold'),
                                      padx=20, pady=10, state='disabled')
        self.save_btn.pack(side='left', padx=5)

        self.tk.Button(save_frame, text="🔄 重置修改", command=self.reset_data,
                      font=('Microsoft YaHei', 11), padx=15, pady=8).pack(side='left', padx=5)

        self.tk.Button(save_frame, text="❌ 退出", command=self.root.quit,
                      font=('Microsoft YaHei', 11), padx=15, pady=8).pack(side='right', padx=5)

        # 状态栏
        self.status_text = self.tk.StringVar(value=f"就绪 | 输出目录: {self.output_dir}")
        self.tk.Label(self.root, textvariable=self.status_text, bd=1, relief='sunken',
                     anchor='w', font=('Microsoft YaHei', 9)).pack(side='bottom', fill='x')

    def _create_category_tab(self, tab, cat_data, cat_key):
        """创建分类标签页"""
        # 创建画布和滚动条
        canvas = self.tk.Canvas(tab)
        scrollbar = self.ttk.Scrollbar(tab, orient="vertical", command=canvas.yview)
        scrollable_frame = self.tk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # 鼠标滚轮
        def on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        canvas.bind_all("<MouseWheel>", on_mousewheel)

        # 存储该分类的所有控件引用
        self.category_frames[cat_key] = {
            'frame': scrollable_frame,
            'widgets': {}
        }

        # 创建项目
        for item in cat_data['items']:
            self._create_item_widget(scrollable_frame, item, cat_key)

    def _create_item_widget(self, parent, item, cat_key):
        """创建单个修改项"""
        item_id = item['id']
        field_type = item['type']

        frame = self.tk.Frame(parent, padx=10, pady=3)
        frame.pack(fill='x', pady=1)

        # 左侧：名称和描述
        left_frame = self.tk.Frame(frame)
        left_frame.pack(side='left', fill='x', expand=True)

        name_label = self.tk.Label(left_frame, text=item['name'], font=('Microsoft YaHei', 10, 'bold'),
                                  width=15, anchor='w')
        name_label.pack(side='left')

        desc_label = self.tk.Label(left_frame, text=item['desc'], font=('Microsoft YaHei', 9),
                                  fg='gray', width=30, anchor='w')
        desc_label.pack(side='left', padx=5)

        # 右侧：当前值和输入控件
        right_frame = self.tk.Frame(frame)
        right_frame.pack(side='right')

        # 当前值显示
        current_var = self.tk.StringVar(value="未加载")
        current_label = self.tk.Label(right_frame, textvariable=current_var,
                                     font=('Microsoft YaHei', 9), fg='blue', width=12)
        current_label.pack(side='left', padx=5)

        # 根据类型创建输入控件
        if field_type == 'bool':
            var = self.tk.BooleanVar(value=False)
            cb = self.tk.Checkbutton(right_frame, text="启用", variable=var,
                                    font=('Microsoft YaHei', 10),
                                    command=lambda: self.on_value_changed(item_id))
            cb.pack(side='left', padx=5)

            self.category_frames[cat_key]['widgets'][item_id] = {
                'type': 'bool',
                'var': var,
                'current_var': current_var,
                'item': item
            }

        elif field_type in ['int', 'float']:
            entry_frame = self.tk.Frame(right_frame)
            entry_frame.pack(side='left', padx=5)

            var = self.tk.StringVar()
            entry = self.tk.Entry(entry_frame, textvariable=var, width=10,
                               font=('Microsoft YaHei', 10), justify='center')
            entry.pack(side='left', padx=2)
            entry.bind('<KeyRelease>', lambda e, iid=item_id: self.on_value_changed(iid))

            if 'max' in item:
                max_btn = self.tk.Button(entry_frame, text="MAX",
                                        command=lambda e=var, m=item['max']: e.set(str(m)),
                                        font=('Microsoft YaHei', 8), padx=5)
                max_btn.pack(side='left', padx=2)

            self.category_frames[cat_key]['widgets'][item_id] = {
                'type': 'entry',
                'var': var,
                'current_var': current_var,
                'item': item
            }

        elif field_type == 'special':
            btn = self.tk.Button(right_frame, text="执行",
                                command=lambda i=item: self.execute_special(i),
                                bg='#FFD93D', font=('Microsoft YaHei', 9, 'bold'), padx=10)
            btn.pack(side='left', padx=5)

            self.category_frames[cat_key]['widgets'][item_id] = {
                'type': 'special',
                'current_var': current_var,
                'item': item
            }

    def on_value_changed(self, item_id):
        """值改变时的回调"""
        self.modified = True
        self.status_text.set("已修改，请记得保存！")

    def browse_file(self):
        """浏览选择文件"""
        filename = self.filedialog.askopenfilename(
            title="选择空洞骑士存档文件",
            filetypes=[("DAT files", "*.dat"), ("All files", "*.*")]
        )
        if filename:
            self.file_entry.delete(0, 'end')
            self.file_entry.insert(0, filename)
            self.load_file(filename)

    def load_from_entry(self):
        """从输入框加载"""
        path = self.file_entry.get().strip()
        if path and Path(path).exists():
            self.load_file(path)
        else:
            self.messagebox.showerror("错误", "文件不存在或路径无效")

    def load_file(self, filepath: str):
        """加载存档文件 - 修复数据读取"""
        try:
            result = self.parser.parse_dat_file(filepath)
            self.original_data = result['json']  # 保留原始嵌套结构
            self.meta = result['meta']
            self.original_name = result['original_name']
            self.current_file = filepath

            # 处理 playerData 嵌套 - 创建扁平化数据用于编辑
            if 'playerData' in self.original_data:
                player_data = self.original_data['playerData']
                # 合并数据：playerData 优先于顶层
                self.data = {**self.original_data, **player_data}
            else:
                self.data = dict(self.original_data)  # 复制

            self.modified = False

            # 更新UI显示当前值
            self._update_all_ui_values()

            # 更新信息栏
            self._update_info_display()

            self.save_btn.config(state='normal')
            self.status_text.set(f"已加载: {filepath}")

            self.messagebox.showinfo("成功", f"已加载存档: {self.original_name}.dat\n\n"
                                    f"吉欧: {self.data.get('geo', 'N/A')}\n"
                                    f"血量: {self.data.get('maxHealth', 'N/A')}\n"
                                    f"完成度: {self.data.get('completionPercentage', 'N/A')}%")

        except Exception as e:
            self.messagebox.showerror("错误", f"加载失败: {str(e)}")
            import traceback
            traceback.print_exc()

    def _update_all_ui_values(self):
        """更新所有UI控件的值"""
        if not self.data:
            return

        for cat_key, cat_data in self.categories.items():
            cat_frame = self.category_frames.get(cat_key)
            if not cat_frame:
                continue

            for item in cat_data['items']:
                item_id = item['id']
                field = item['field']

                widget_data = cat_frame['widgets'].get(item_id)
                if not widget_data:
                    continue

                # 获取当前值
                current_val = self.data.get(field)
                if current_val is None:
                    current_val = "无"

                # 更新当前值显示
                widget_data['current_var'].set(f"当前: {current_val}")

                # 更新输入控件
                if item['type'] == 'bool':
                    widget_data['var'].set(bool(current_val) if current_val is not None else False)
                elif item['type'] in ['int', 'float']:
                    widget_data['var'].set(str(current_val) if current_val is not None else "")

    def _update_info_display(self):
        """更新信息栏显示"""
        if not self.data:
            return

        geo = self.data.get('geo', 0)
        health = self.data.get('maxHealth', 0)
        nail = self.data.get('nailSmithUpgrades', 0)
        completion = self.data.get('completionPercentage', 0)
        playtime = self.data.get('playTime', 0) / 3600

        info = (f"文件: {self.original_name}.dat | "
                f"💰吉欧: {geo} | "
                f"❤️血量: {health} | "
                f"⚔️骨钉: {nail}级 | "
                f"🏆完成度: {completion}% | "
                f"⏱️游戏时间: {playtime:.1f}小时")
        self.info_text.set(info)

    def execute_special(self, item: dict):
        """执行特殊操作"""
        if not self.data:
            self.messagebox.showwarning("警告", "请先加载存档文件")
            return

        action = item.get('action', '')
        result = self.apply_special_action(self.data, action)
        self.modified = True

        # 更新UI显示
        self._update_all_ui_values()
        self._update_info_display()

        self.status_text.set(f"已执行: {item['name']} | 请保存！")
        self.messagebox.showinfo("完成", result)

    def collect_all_modifications(self) -> list:
        """收集所有修改"""
        if not self.data:
            return []

        modifications = []

        for cat_key, cat_data in self.categories.items():
            cat_frame = self.category_frames.get(cat_key)
            if not cat_frame:
                continue

            for item in cat_data['items']:
                item_id = item['id']
                field = item['field']
                field_type = item['type']

                if field_type == 'special':
                    continue

                widget_data = cat_frame['widgets'].get(item_id)
                if not widget_data:
                    continue

                current_val = self.data.get(field)

                # 获取UI中的新值
                if field_type == 'bool':
                    new_val = widget_data['var'].get()
                else:
                    val_str = widget_data['var'].get().strip()
                    if not val_str:
                        continue
                    try:
                        if field_type == 'int':
                            new_val = int(val_str)
                        else:
                            new_val = float(val_str)
                    except ValueError:
                        continue

                # 检查是否有变化
                if current_val != new_val:
                    # 应用修改到数据
                    result = self.apply_modification(self.data, item, new_val)
                    modifications.append(result)

        return modifications

    def save_file(self):
        """保存修改后的文件"""
        if not self.data or not self.meta:
            self.messagebox.showwarning("警告", "没有可保存的数据")
            return

        # 首先收集所有修改到 self.data
        modifications = self.collect_all_modifications()

        # 准备保存数据 - 需要更新原始嵌套结构
        save_data = self.original_data

        if 'playerData' in save_data:
            # 更新 playerData 内的值
            for key in save_data['playerData'].keys():
                if key in self.data:
                    save_data['playerData'][key] = self.data[key]
            # 同时更新顶层字段
            for key in ['geo', 'nailSmithUpgrades', 'completionPercentage']:
                if key in self.data:
                    save_data[key] = self.data[key]
        else:
            save_data = self.data

        # 保存
        try:
            json_path, dat_path = self.save_files(save_data, self.meta, self.original_name)

            msg = f"文件已保存到:\n\n📄 JSON:\n{json_path}\n\n🎮 DAT:\n{dat_path}"
            if modifications:
                msg += f"\n\n本次修改 ({len(modifications)}项):\n"
                msg += "\n".join([f"• {m}" for m in modifications[:15]])
                if len(modifications) > 15:
                    msg += f"\n... 等共{len(modifications)}项"

            self.messagebox.showinfo("保存成功", msg)
            self.modified = False
            self.status_text.set(f"已保存: {dat_path.name}")

        except Exception as e:
            self.messagebox.showerror("保存失败", str(e))
            import traceback
            traceback.print_exc()

    def max_everything(self):
        """一键满配"""
        if not self.data:
            self.messagebox.showwarning("警告", "请先加载存档文件")
            return

        if self.messagebox.askyesno("确认", "这将把所有数值设为最大值，确定继续？"):
            self.apply_special_action(self.data, 'max_everything')
            self._update_all_ui_values()
            self._update_info_display()
            self.modified = True
            self.messagebox.showinfo("完成", "一键满配完成！所有数值已设为最大")

    def quick_set(self, field: str, value: Any):
        """快速设置"""
        if not self.data:
            self.messagebox.showwarning("警告", "请先加载存档文件")
            return

        self.data[field] = value
        self._update_all_ui_values()
        self._update_info_display()
        self.modified = True
        self.status_text.set(f"已设置: {field} = {value} | 请保存！")

    def max_health(self):
        """满血"""
        if not self.data:
            return
        self.data['maxHealth'] = 9
        self.data['health'] = 9
        self.data['maxHealthBase'] = 9
        self.data['heartPieces'] = 4
        self._update_all_ui_values()
        self._update_info_display()
        self.modified = True
        self.status_text.set("已设置满血量 | 请保存！")

    def max_nail(self):
        """满骨钉"""
        if not self.data:
            return
        self.data['nailSmithUpgrades'] = 4
        self.data['nailDamage'] = 21
        self.data['honedNail'] = True
        self._update_all_ui_values()
        self._update_info_display()
        self.modified = True
        self.status_text.set("已设置满级骨钉 | 请保存！")

    def all_skills(self):
        """全技能"""
        if not self.data:
            return
        skills = ['hasDash', 'hasShadowDash', 'hasWalljump', 'hasDoubleJump',
                 'hasSuperDash', 'hasAcidArmour', 'canDash', 'canWallJump',
                 'canSuperDash', 'canShadowDash']
        for skill in skills:
            self.data[skill] = True
        self._update_all_ui_values()
        self._update_info_display()
        self.modified = True
        self.status_text.set("已解锁全部技能 | 请保存！")

    def reset_data(self):
        """重置"""
        if not self.current_file:
            return

        if self.messagebox.askyesno("确认", "确定要重新加载原始文件？所有未保存修改将丢失。"):
            self.load_file(self.current_file)


class WebEditor(SaveEditorCore):
    """Web界面版本 - 基于Flask"""

    def __init__(self):
        super().__init__()
        self.app = None
        self.current_data = None
        self.current_meta = None
        self.current_name = ""
        self.original_data = None

    def run(self, input_file: str = None, port: int = 5000, host: str = '127.0.0.1'):
        """启动Web服务器"""
        try:
            from flask import Flask, render_template, request, jsonify, send_file
            from flask_cors import CORS
            self.flask = __import__('flask')
        except ImportError:
            print("❌ 无法导入Flask，请安装: pip install flask flask-cors")
            print("   或使用CLI/GUI模式")
            return False

        self.app = self.flask.Flask(__name__,
                                   template_folder=str(self.script_dir / 'templates'),
                                   static_folder=str(self.script_dir / 'static'))
        CORS(self.app)

        # 确保模板目录存在
        self._create_templates()

        # 注册路由
        self._register_routes()

        # 如果提供了文件，自动加载
        if input_file and Path(input_file).exists():
            self._load_file(input_file)

        # 打开浏览器
        url = f"http://{host}:{port}"
        print(f"\n🌐 Web界面启动中...")
        print(f"   访问地址: {url}")
        print(f"   按 Ctrl+C 停止服务器\n")

        threading.Timer(1.5, lambda: webbrowser.open(url)).start()

        try:
            self.app.run(host=host, port=port, debug=False)
        except KeyboardInterrupt:
            print("\n👋 服务器已停止")
        finally:
            # 关闭时删除模板文件
            self._cleanup_templates()

        return True

    def _cleanup_templates(self):
        """清理模板文件"""
        try:
            template_path = self.script_dir / 'templates' / 'index.html'
            if template_path.exists():
                template_path.unlink()
                print(f"\n🗑️  已清理模板文件: {template_path}")
        except Exception as e:
            print(f"\n⚠️  清理模板文件失败: {e}")

    def _create_templates(self):
        """创建HTML模板"""
        templates_dir = self.script_dir / 'templates'
        templates_dir.mkdir(exist_ok=True)

        html_content = '''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
    <meta http-equiv="Pragma" content="no-cache">
    <meta http-equiv="Expires" content="0">
    <title>🎮 空洞骑士存档修改器</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Microsoft YaHei', 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            min-height: 100vh;
            color: #eee;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }

        header {
            text-align: center;
            padding: 30px 0;
            border-bottom: 2px solid #e94560;
            margin-bottom: 30px;
        }

        h1 {
            font-size: 2.5em;
            color: #e94560;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.5);
            margin-bottom: 10px;
        }

        .subtitle {
            color: #aaa;
            font-size: 1.1em;
        }

        .info-panel {
            background: rgba(255,255,255,0.05);
            border-radius: 15px;
            padding: 20px;
            margin-bottom: 20px;
            border: 1px solid rgba(233, 69, 96, 0.3);
        }

        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }

        .info-item {
            background: rgba(0,0,0,0.2);
            padding: 15px;
            border-radius: 10px;
            text-align: center;
        }

        .info-label {
            color: #888;
            font-size: 0.9em;
            margin-bottom: 5px;
        }

        .info-value {
            color: #e94560;
            font-size: 1.5em;
            font-weight: bold;
        }

        .file-section {
            background: rgba(255,255,255,0.05);
            border-radius: 15px;
            padding: 20px;
            margin-bottom: 20px;
        }

        .file-input-wrapper {
            display: flex;
            gap: 10px;
            align-items: center;
            flex-wrap: wrap;
        }

        input[type="file"], input[type="text"] {
            background: rgba(0,0,0,0.3);
            border: 2px solid #e94560;
            color: #fff;
            padding: 12px 20px;
            border-radius: 8px;
            font-size: 1em;
            flex: 1;
            min-width: 300px;
        }

        input[type="file"]::file-selector-button {
            background: #e94560;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 5px;
            cursor: pointer;
            margin-right: 15px;
        }

        button {
            background: linear-gradient(135deg, #e94560 0%, #c73e54 100%);
            color: white;
            border: none;
            padding: 12px 30px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 1em;
            font-weight: bold;
            transition: all 0.3s;
            box-shadow: 0 4px 15px rgba(233, 69, 96, 0.3);
        }

        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(233, 69, 96, 0.4);
        }

        button.secondary {
            background: linear-gradient(135deg, #4a4a6a 0%, #3a3a5a 100%);
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
        }

        button.secondary:hover {
            box-shadow: 0 6px 20px rgba(0,0,0,0.3);
        }

        button.success {
            background: linear-gradient(135deg, #4CAF50 0%, #45a049 100%);
            box-shadow: 0 4px 15px rgba(76, 175, 80, 0.3);
        }

        .tabs {
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 8px;
            margin-bottom: 0;
            padding: 10px;
            background: rgba(0,0,0,0.2);
            border-radius: 12px 12px 0 0;
            border: 1px solid rgba(255,255,255,0.1);
            border-bottom: 2px solid rgba(233, 69, 96, 0.8);
        }

        .tab {
            background: rgba(255,255,255,0.08);
            border: 1px solid rgba(255,255,255,0.1);
            color: #aaa;
            padding: 10px 5px;
            cursor: pointer;
            border-radius: 8px 8px 0 0;
            transition: all 0.3s;
            font-size: 0.9em;
            text-align: center;
        }

        .tab:hover {
            background: rgba(233, 69, 96, 0.3);
            color: white;
            transform: translateY(-2px);
        }

        .tab.active {
            background: rgba(233, 69, 96, 0.8);
            color: white;
            box-shadow: 0 4px 15px rgba(233, 69, 96, 0.4);
            border-bottom: 2px solid rgba(233, 69, 96, 0.8);
            margin-bottom: -2px;
        }

        .tab-content {
            display: none;
            background: rgba(255,255,255,0.05);
            border-radius: 0 0 15px 15px;
            padding: 20px;
            animation: fadeIn 0.3s;
            border: 1px solid rgba(255,255,255,0.1);
            border-top: none;
        }

        .tab-content.active {
            display: block;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .item-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
            gap: 15px;
        }

        .edit-item {
            background: rgba(0,0,0,0.2);
            border-radius: 10px;
            padding: 15px;
            border: 1px solid rgba(255,255,255,0.1);
            transition: all 0.3s;
        }

        .edit-item:hover {
            border-color: #e94560;
            transform: translateY(-2px);
        }

        .item-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }

        .item-name {
            font-weight: bold;
            color: #fff;
            font-size: 1.1em;
        }

        .item-desc {
            color: #888;
            font-size: 0.85em;
            margin-bottom: 10px;
        }

        .item-current {
            color: #4CAF50;
            font-size: 0.9em;
        }

        .input-group {
            display: flex;
            gap: 10px;
            align-items: center;
        }

        .edit-item input[type="number"], .edit-item input[type="text"] {
            background: rgba(0,0,0,0.3);
            border: 1px solid #555;
            color: #fff;
            padding: 8px 12px;
            border-radius: 5px;
            width: 100px;
            text-align: center;
        }

        .edit-item input[type="checkbox"] {
            width: 20px;
            height: 20px;
            accent-color: #e94560;
        }

        .max-btn {
            background: #e94560;
            color: white;
            border: none;
            padding: 5px 12px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 0.85em;
        }

        .quick-actions {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            margin-bottom: 20px;
            padding: 20px;
            background: rgba(233, 69, 96, 0.1);
            border-radius: 15px;
        }

        .quick-actions button {
            flex: 1;
            min-width: 120px;
            padding: 15px 30px;
            font-size: 1.1em;
        }

        .status-bar {
            position: fixed;
            bottom: 0;
            left: 0;
            right: 0;
            background: rgba(0,0,0,0.9);
            padding: 15px;
            text-align: center;
            border-top: 2px solid #e94560;
        }

        .toast {
            position: fixed;
            top: 20px;
            right: 20px;
            background: #4CAF50;
            color: white;
            padding: 15px 25px;
            border-radius: 8px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.3);
            display: none;
            animation: slideIn 0.3s;
            z-index: 1000;
        }

        @keyframes slideIn {
            from { transform: translateX(400px); }
            to { transform: translateX(0); }
        }

        .toast.error {
            background: #f44336;
        }

        .toast.show {
            display: block;
        }

        .hidden {
            display: none !important;
        }

        .special-btn {
            background: linear-gradient(135deg, #FFD93D 0%, #F6AD55 100%);
            color: #333;
            width: 100%;
            margin-top: 10px;
        }

        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid rgba(255,255,255,.3);
            border-radius: 50%;
            border-top-color: #e94560;
            animation: spin 1s ease-in-out infinite;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🎮 空洞骑士存档修改器</h1>
            <p class="subtitle">Hollow Knight Save Editor - Web Edition</p>
        </header>

        <div class="file-section">
            <h3 style="margin-bottom: 15px; color: #e94560;">📂 加载存档</h3>
            <div class="file-input-wrapper">
                <input type="file" id="fileInput" accept=".dat" onchange="handleFileSelect(this)">
                <button onclick="uploadFile()">📂 加载存档</button>
                <button class="secondary" onclick="resetAll()">🔄 重置</button>
            </div>
        </div>

        <div id="infoPanel" class="info-panel hidden">
            <div class="info-grid">
                <div class="info-item">
                    <div class="info-label">吉欧</div>
                    <div class="info-value" id="infoGeo">-</div>
                </div>
                <div class="info-item">
                    <div class="info-label">血量</div>
                    <div class="info-value" id="infoHealth">-</div>
                </div>
                <div class="info-item">
                    <div class="info-label">骨钉等级</div>
                    <div class="info-value" id="infoNail">-</div>
                </div>
                <div class="info-item">
                    <div class="info-label">完成度</div>
                    <div class="info-value" id="infoCompletion">-</div>
                </div>
                <div class="info-item">
                    <div class="info-label">游戏时间</div>
                    <div class="info-value" id="infoTime">-</div>
                </div>
            </div>
        </div>

        <div id="editorSection" class="hidden">
            <div class="quick-actions">
                <button onclick="quickAction('max')" style="background: linear-gradient(135deg, #FF6B6B 0%, #EE5A5A 100%);">🌟 一键满配</button>
                <button onclick="quickAction('geo')" style="background: linear-gradient(135deg, #4ECDC4 0%, #44B5AD 100%);">💰 满金钱</button>
                <button onclick="quickAction('health')" style="background: linear-gradient(135deg, #FF6B6B 0%, #EE5A5A 100%);">❤️ 满血量</button>
                <button onclick="quickAction('nail')" style="background: linear-gradient(135deg, #95E1D3 0%, #7BC8B8 100%); color: #333;">⚔️ 满骨钉</button>
                <button onclick="quickAction('skills')" style="background: linear-gradient(135deg, #F38181 0%, #E06C6C 100%);">🏃 全技能</button>
            </div>

            <div class="tabs" id="categoryTabs">
                <!-- 动态生成 -->
            </div>

            <div id="tabContents">
                <!-- 动态生成 -->
            </div>

            <div style="text-align: center; margin: 30px 0;">
                <button class="success" onclick="saveFile()" style="font-size: 1.3em; padding: 20px 50px;">
                    💾 保存修改并下载
                </button>
            </div>
        </div>
    </div>

    <div class="status-bar" id="statusBar">
        就绪 | 输出目录: {{ output_dir }}
    </div>

    <div class="toast" id="toast"></div>

    <script>
        let currentData = null;
        let originalName = '';
        let modifiedFields = new Set();

        const VERSION = Date.now();

        const categories = {{ categories|tojson }};

        function showToast(message, isError = false) {
            const toast = document.getElementById('toast');
            toast.textContent = message;
            toast.className = 'toast show' + (isError ? ' error' : '');
            setTimeout(() => toast.classList.remove('show'), 3000);
        }

        function handleFileSelect(input) {
            if (input.files && input.files[0]) {
                const file = input.files[0];
                if (!file.name.endsWith('.dat')) {
                    showToast('请选择 .dat 格式的存档文件', true);
                    input.value = '';
                    return;
                }
            }
        }

        async function uploadFile() {
            const input = document.getElementById('fileInput');
            if (!input.files || !input.files[0]) {
                showToast('请先选择存档文件', true);
                return;
            }

            const file = input.files[0];
            const formData = new FormData();
            formData.append('file', file);

            showToast('正在加载...');

            try {
                const response = await fetch('/api/load?t=' + VERSION, {
                method: 'POST',
                body: formData
                });

                const result = await response.json();

                if (result.success) {
                    currentData = result.data;
                    originalName = result.name;
                    displayInfo(result.info);
                    generateEditor();
                    document.getElementById('editorSection').classList.remove('hidden');
                    document.getElementById('infoPanel').classList.remove('hidden');
                    showToast('存档加载成功！');
                    updateStatus('已加载: ' + result.name);
                } else {
                    showToast(result.error || '加载失败', true);
                }
            } catch (err) {
                showToast('网络错误: ' + err.message, true);
            }
        }

        function displayInfo(info) {
            document.getElementById('infoGeo').textContent = info.geo;
            document.getElementById('infoHealth').textContent = info.health;
            document.getElementById('infoNail').textContent = info.nail;
            document.getElementById('infoCompletion').textContent = info.completion + '%';
            document.getElementById('infoTime').textContent = info.playtime + 'h';
        }

        function generateEditor() {
            const tabsContainer = document.getElementById('categoryTabs');
            const contentsContainer = document.getElementById('tabContents');

            tabsContainer.innerHTML = '';
            contentsContainer.innerHTML = '';

            Object.entries(categories).sort((a, b) => parseInt(a[0]) - parseInt(b[0])).forEach(([key, cat], index) => {
                // 创建标签
                const tab = document.createElement('button');
                tab.className = 'tab' + (index === 0 ? ' active' : '');
                tab.textContent = cat.name;
                tab.onclick = () => switchTab(key);
                tab.dataset.tab = key;
                tabsContainer.appendChild(tab);

                // 创建内容
                const content = document.createElement('div');
                content.className = 'tab-content' + (index === 0 ? ' active' : '');
                content.dataset.content = key;

                const grid = document.createElement('div');
                grid.className = 'item-grid';

                cat.items.forEach(item => {
                    const div = createEditItem(item);
                    grid.appendChild(div);
                });

                content.appendChild(grid);
                contentsContainer.appendChild(content);
            });
        }

        function createEditItem(item) {
            const div = document.createElement('div');
            div.className = 'edit-item';
            div.dataset.field = item.field;

            const currentValue = currentData[item.field] !== undefined ? currentData[item.field] : 'N/A';

            let inputHtml = '';
            if (item.type === 'bool') {
                const checked = currentValue ? 'checked' : '';
                inputHtml = `
                    <div class="input-group">
                        <input type="checkbox" id="${item.id}" ${checked}
                               onchange="markModified('${item.id}', this.checked)">
                        <label for="${item.id}">启用</label>
                    </div>
                `;
            } else if (item.type === 'int' || item.type === 'float') {
                const maxAttr = item.max ? `max="${item.max}"` : '';
                const step = item.type === 'float' ? 'step="0.1"' : '';
                inputHtml = `
                    <div class="input-group">
                        <input type="number" id="${item.id}" value="${currentValue}"
                               ${maxAttr} ${step} onchange="markModified('${item.id}', this.value)">
                        ${item.max ? `<button class="max-btn" onclick="setMax('${item.id}', ${item.max})">MAX</button>` : ''}
                    </div>
                `;
            } else if (item.type === 'special') {
                inputHtml = `<button class="special-btn" onclick="executeSpecial('${item.action}', '${item.name}')">${item.desc}</button>`;
            }

            div.innerHTML = `
                <div class="item-header">
                    <span class="item-name">${item.name}</span>
                    <span class="item-current" id="current_${item.id}">当前: ${currentValue}</span>
                </div>
                <div class="item-desc">${item.desc}</div>
                ${inputHtml}
            `;

            return div;
        }

        function switchTab(key) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

            document.querySelector(`[data-tab="${key}"]`).classList.add('active');
            document.querySelector(`[data-content="${key}"]`).classList.add('active');
        }

        function markModified(id, value) {
            modifiedFields.add(id);
            document.getElementById('current_' + id).textContent = '已修改: ' + value;
            document.getElementById('current_' + id).style.color = '#FFD93D';
            updateStatus('已修改 ' + modifiedFields.size + ' 项，记得保存！');
        }

        function setMax(id, max) {
            document.getElementById(id).value = max;
            markModified(id, max);
        }

        async function executeSpecial(action, name) {
            if (!confirm(`确定要执行 "${name}" 吗？`)) return;

            try {
                const response = await fetch('/api/special?t=' + VERSION, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({action: action})
                });

                const result = await response.json();
                if (result.success) {
                    currentData = result.data;
                    generateEditor(); // 刷新显示
                    showToast(result.message);
                    modifiedFields.add('special_' + action);
                }
            } catch (err) {
                showToast('执行失败: ' + err.message, true);
            }
        }

        async function quickAction(type) {
            if (!currentData) {
                showToast('请先加载存档', true);
                return;
            }

            const actions = {
                'max': '一键满配',
                'geo': '满金钱',
                'health': '满血量',
                'nail': '满骨钉',
                'skills': '全技能'
            };

            if (!confirm(`确定要执行 "${actions[type]}" 吗？`)) return;

            try {
                const response = await fetch('/api/quick', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({type: type})
                });

                const result = await response.json();
                if (result.success) {
                    currentData = result.data;
                    displayInfo(result.info);
                    generateEditor();
                    showToast(actions[type] + ' 完成！');
                    modifiedFields.add('quick_' + type);
                }
            } catch (err) {
                showToast('执行失败: ' + err.message, true);
            }
        }

        async function saveFile() {
            if (!currentData) {
                showToast('没有可保存的数据', true);
                return;
            }

            // 收集所有修改
            const changes = {};
            document.querySelectorAll('.edit-item').forEach(item => {
                const field = item.dataset.field;
                if (!field || field === '_special') return;

                const input = item.querySelector('input[type="number"], input[type="checkbox"]');
                if (input) {
                    if (input.type === 'checkbox') {
                        changes[field] = input.checked;
                    } else {
                        const val = parseFloat(input.value);
                        changes[field] = isNaN(val) ? input.value : val;
                    }
                }
            });

            try {
                const response = await fetch('/api/save?t=' + VERSION, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        changes: changes,
                        name: originalName
                    })
                });

                const result = await response.json();

                if (result.success) {
                    showToast('保存成功！正在下载...');

                    // 下载文件
                    window.location.href = '/api/download/' + result.dat_file;
                    updateStatus('已保存到: ' + result.output_dir);
                } else {
                    showToast(result.error || '保存失败', true);
                }
            } catch (err) {
                showToast('保存失败: ' + err.message, true);
            }
        }

        function resetAll() {
            if (!confirm('确定要重置所有修改？未保存的修改将丢失。')) return;

            currentData = null;
            originalName = '';
            modifiedFields.clear();

            document.getElementById('fileInput').value = '';
            document.getElementById('editorSection').classList.add('hidden');
            document.getElementById('infoPanel').classList.add('hidden');

            updateStatus('就绪');
            showToast('已重置');
        }

        function updateStatus(msg) {
            document.getElementById('statusBar').textContent = msg + ' | 输出目录: {{ output_dir }}';
        }
    </script>
</body>
</html>'''

        template_path = templates_dir / 'index.html'
        if not template_path.exists():
            template_path.write_text(html_content, encoding='utf-8')

    def _register_routes(self):
        """注册Flask路由"""

        from functools import wraps

        def no_cache(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                response = f(*args, **kwargs)
                if isinstance(response, tuple):
                    response = self.flask.make_response(response[0])
                elif not isinstance(response, self.flask.Response):
                    response = self.flask.make_response(response)
                response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
                response.headers['Pragma'] = 'no-cache'
                response.headers['Expires'] = '0'
                return response
            return decorated_function

        @self.app.route('/')
        def index():
            response = self.flask.make_response(
                self.flask.render_template('index.html',
                                         categories=self.categories,
                                         output_dir=str(self.output_dir))
            )
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
            return response

        @self.app.route('/api/load', methods=['POST'])
        @no_cache
        def api_load():
            if 'file' not in self.flask.request.files:
                return self.flask.jsonify({'success': False, 'error': '没有文件'})

            file = self.flask.request.files['file']
            if file.filename == '':
                return self.flask.jsonify({'success': False, 'error': '文件名为空'})

            if not file.filename.endswith('.dat'):
                return self.flask.jsonify({'success': False, 'error': '必须是.dat文件'})

            try:
                # 保存临时文件
                temp_path = self.script_dir / 'temp_upload.dat'
                file.save(str(temp_path))

                # 解析
                result = self.parser.parse_dat_file(temp_path)
                self.original_data = result['json']
                self.current_meta = result['meta']
                self.current_name = result['original_name']

                # 扁平化数据
                if 'playerData' in self.original_data:
                    player_data = self.original_data['playerData']
                    self.current_data = {**self.original_data, **player_data}
                else:
                    self.current_data = dict(self.original_data)

                temp_path.unlink()  # 删除临时文件

                # 提取信息
                info = {
                    'name': self.current_name,
                    'geo': self.current_data.get('geo', 0),
                    'health': self.current_data.get('maxHealth', 0),
                    'nail': self.current_data.get('nailSmithUpgrades', 0),
                    'completion': self.current_data.get('completionPercentage', 0),
                    'playtime': round(self.current_data.get('playTime', 0) / 3600, 1)
                }

                return self.flask.jsonify({
                    'success': True,
                    'data': self.current_data,
                    'name': self.current_name,
                    'info': info
                })

            except Exception as e:
                import traceback
                traceback.print_exc()
                return self.flask.jsonify({'success': False, 'error': str(e)})

        @self.app.route('/api/special', methods=['POST'])
        def api_special():
            if not self.current_data:
                return self.flask.jsonify({'success': False, 'error': '未加载存档'})

            data = self.flask.request.get_json()
            action = data.get('action', '')

            try:
                message = self.apply_special_action(self.current_data, action)
                return self.flask.jsonify({
                    'success': True,
                    'data': self.current_data,
                    'message': message
                })
            except Exception as e:
                return self.flask.jsonify({'success': False, 'error': str(e)})

        @self.app.route('/api/quick', methods=['POST'])
        @no_cache
        def api_quick():
            if not self.current_data:
                return self.flask.jsonify({'success': False, 'error': '未加载存档'})

            data = self.flask.request.get_json()
            qtype = data.get('type', '')

            if qtype == 'max':
                self.apply_special_action(self.current_data, 'max_everything')
            elif qtype == 'geo':
                self.current_data['geo'] = 99999
            elif qtype == 'health':
                self.current_data['maxHealth'] = 9
                self.current_data['health'] = 9
                self.current_data['maxHealthBase'] = 9
                self.current_data['heartPieces'] = 4
            elif qtype == 'nail':
                self.current_data['nailSmithUpgrades'] = 4
                self.current_data['nailDamage'] = 21
                self.current_data['honedNail'] = True
            elif qtype == 'skills':
                for skill in ['hasDash', 'hasShadowDash', 'hasWalljump',
                             'hasDoubleJump', 'hasSuperDash', 'hasAcidArmour']:
                    self.current_data[skill] = True

            info = {
                'name': self.current_name,
                'geo': self.current_data.get('geo', 0),
                'health': self.current_data.get('maxHealth', 0),
                'nail': self.current_data.get('nailSmithUpgrades', 0),
                'completion': self.current_data.get('completionPercentage', 0),
                'playtime': round(self.current_data.get('playTime', 0) / 3600, 1)
            }

            return self.flask.jsonify({
                'success': True,
                'data': self.current_data,
                'info': info
            })

        @self.app.route('/api/save', methods=['POST'])
        @no_cache
        def api_save():
            if not self.current_data or not self.current_meta:
                return self.flask.jsonify({'success': False, 'error': '未加载存档'})

            data = self.flask.request.get_json()
            changes = data.get('changes', {})
            name = data.get('name', 'unknown')

            try:
                # 应用修改
                for field, value in changes.items():
                    self.current_data[field] = value

                # 准备保存数据
                save_data = self.original_data
                if 'playerData' in save_data:
                    for key in save_data['playerData'].keys():
                        if key in self.current_data:
                            save_data['playerData'][key] = self.current_data[key]
                    for key in ['geo', 'nailSmithUpgrades', 'completionPercentage']:
                        if key in self.current_data:
                            save_data[key] = self.current_data[key]
                else:
                    save_data = self.current_data

                # 保存文件
                json_path, dat_path = self.save_files(save_data, self.current_meta, name)

                return self.flask.jsonify({
                    'success': True,
                    'json_file': json_path.name,
                    'dat_file': dat_path.name,
                    'output_dir': str(self.output_dir)
                })

            except Exception as e:
                import traceback
                traceback.print_exc()
                return self.flask.jsonify({'success': False, 'error': str(e)})

        @self.app.route('/api/download/<filename>')
        @no_cache
        def api_download(filename):
            file_path = self.output_dir / filename
            if file_path.exists():
                return self.flask.send_file(str(file_path), as_attachment=True)
            return '文件不存在', 404

    def _load_file(self, filepath: str):
        """预加载文件"""
        try:
            result = self.parser.parse_dat_file(filepath)
            self.original_data = result['json']
            self.current_meta = result['meta']
            self.current_name = result['original_name']

            if 'playerData' in self.original_data:
                player_data = self.original_data['playerData']
                self.current_data = {**self.original_data, **player_data}
            else:
                self.current_data = dict(self.original_data)

        except Exception as e:
            print(f"预加载失败: {e}")


def main():
    parser = argparse.ArgumentParser(
        description='空洞骑士存档修改器',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用方式:
  python hk.py <存档文件.dat>              # CLI交互模式
  python hk.py --gui [存档文件.dat]         # GUI图形界面
  python hk.py --web [存档文件.dat]         # Web界面 (http://127.0.0.1:5000)
  python hk.py --web --port 8080            # Web界面指定端口
  python hk.py <存档文件.dat> --preset max  # 快速修改
        """
    )

    parser.add_argument('file', nargs='?', help='输入的 .dat 存档文件')
    parser.add_argument('--gui', action='store_true', help='启动图形界面')
    parser.add_argument('--web', action='store_true', help='启动Web界面')
    parser.add_argument('--port', type=int, default=5000, help='Web服务器端口 (默认5000)')
    parser.add_argument('--host', default='127.0.0.1', help='Web服务器地址 (默认127.0.0.1)')
    parser.add_argument('--preset', choices=['max', 'geo', 'health', 'skills'],
                       help='快速修改预设（仅CLI）')

    args = parser.parse_args()

    if args.web:
        # Web模式
        editor = WebEditor()
        editor.run(args.file, port=args.port, host=args.host)

    elif args.gui:
        # GUI模式
        try:
            import tkinter as tk
        except ImportError:
            print("❌ 无法导入tkinter，尝试启动Web界面...")
            print("   或者使用: sudo apt-get install python3-tk")
            editor = WebEditor()
            editor.run(args.file)
            return

        editor = GUIEditor()
        editor.run(args.file)

    else:
        # CLI模式
        editor = CLIEditor()

        if args.preset:
            if not args.file:
                print("错误: --preset 需要提供文件路径")
                sys.exit(1)
            editor.quick_modify(args.file, args.preset)
        elif args.file:
            editor.interactive_edit(args.file)
        else:
            print("用法: python hk.py <存档文件.dat>")
            print("      python hk.py --gui")
            print("      python hk.py --web")
            print("      python hk.py --web --port 8080")
            print("\n使用 --web 参数启动Web界面（推荐，无需额外依赖）")
            sys.exit(1)


if __name__ == "__main__":
    main()
