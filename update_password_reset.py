#!/usr/bin/env python3
"""
密码重置功能数据库迁移
运行: python update_password_reset.py
"""

import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app, db

def create_password_reset_table():
    """创建密码重置表"""
    with app.app_context():
        try:
            print("🔄 创建密码重置表...")
            
            # 创建表
            db.create_all()
            
            print("✅ 密码重置表创建完成")
            print("🎉 密码管理功能已就绪！")
            
        except Exception as e:
            print(f"❌ 迁移失败: {str(e)}")

if __name__ == '__main__':
    create_password_reset_table()