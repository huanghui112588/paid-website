"""
类型存根文件，帮助 Pylance 理解 SQLAlchemy 关系
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sqlalchemy.orm import RelationshipProperty
    
    class User:
        payments: RelationshipProperty
        questions: RelationshipProperty
    
    class Payment:
        user: RelationshipProperty
    
    class Question:
        user: RelationshipProperty