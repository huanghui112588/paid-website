#!/usr/bin/env python3
"""
数据库迁移脚本 - 创建索引和优化表结构
运行: python migration.py
"""

import os
import sys

# 添加当前目录到Python路径
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app, db
from sqlalchemy import text

def create_indexes():
    """创建数据库索引"""
    with app.app_context():
        try:
            print("🔄 开始创建数据库索引...")
            
            # 为现有表创建索引
            indexes_sql = [
                # User 表索引
                "CREATE INDEX IF NOT EXISTS idx_user_username ON \"user\" (username);",
                "CREATE INDEX IF NOT EXISTS idx_user_email ON \"user\" (email);",
                "CREATE INDEX IF NOT EXISTS idx_user_create_time ON \"user\" (create_time);",
                
                # Payment 表索引
                "CREATE INDEX IF NOT EXISTS idx_payment_user_id ON payment (user_id);",
                "CREATE INDEX IF NOT EXISTS idx_payment_status ON payment (status);",
                "CREATE INDEX IF NOT EXISTS idx_payment_create_time ON payment (create_time);",
                "CREATE INDEX IF NOT EXISTS idx_payment_user_status ON payment (user_id, status);",
                
                # Question 表索引
                "CREATE INDEX IF NOT EXISTS idx_question_user_id ON question (user_id);",
                "CREATE INDEX IF NOT EXISTS idx_question_answered ON question (answered);",
                "CREATE INDEX IF NOT EXISTS idx_question_create_time ON question (create_time);",
                "CREATE INDEX IF NOT EXISTS idx_question_user_answered ON question (user_id, answered);"
            ]
            
            for sql in indexes_sql:
                try:
                    # 使用 text() 包装 SQL 语句
                    db.session.execute(text(sql))
                    print(f"✅ 执行: {sql.split('ON')[1].split('(')[0].strip()}")
                except Exception as e:
                    print(f"⚠️  索引可能已存在: {e}")
            
            db.session.commit()
            print("🎉 数据库索引创建完成！")
            
        except Exception as e:
            db.session.rollback()
            print(f"❌ 数据库迁移失败: {str(e)}")

if __name__ == '__main__':
    create_indexes()