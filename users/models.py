from sqlalchemy import Column, String, Integer
from database import Base, ModelManagerMixin


class User(Base, ModelManagerMixin):
    __tablename__ = "users"
    __mapper_args__ = {"eager_defaults": True}

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(length=50), nullable=False, unique=True)
    password = Column(String(100), nullable=False)

    def __str__(self):
        return f"User: {self.username}"
