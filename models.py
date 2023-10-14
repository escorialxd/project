from sqlalchemy import Boolean, Column, ForeignKey, Integer, String 
from sqlalchemy.orm import relationship 
from database import Base 


#Классы Юзеров 


class User(Base): 
    """User model for db"""

    __tablename__ = "users" 
    id = Column(Integer, primary_key=True, index=True) 
    email = Column(String, unique=True, index=True) 
    hashed_password = Column(String) 
    is_active = Column(Boolean, default=True) 
    name = Column(String, index=True) 
    surname = Column(String, index=True) 
    telephone_number = Column(String, index=True) 
    items = relationship("Item", back_populates="owner") 

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'is_active': self.is_active,
            'name': self.name,
            'surname': self.surname,
            'telephone_number': self.telephone_number,
            'items': [item.to_dict() for item in self.items] if hasattr(self, 'items') else [],
        }


class UserCreate: 
    def __init__(self, email: str, password: str, name:str, surname:str, telephone_number:str): 
        self.email = email 
        self.password = password 
        self.name = name 
        self.surname = surname 
        self.telephone_number = telephone_number 


class UserUpdate: 
    def __init__(self, email: str, password: str, name:str, surname:str, telephone_number:str): 
        self.email = email 
        self.password = password 
        self.name = name 
        self.surname = surname 
        self.telephone_number = telephone_number 


#Классы Итемов (К примеры какие-нибудь курсы) 


class Item(Base): 
    __tablename__ = "items" 
    id = Column(Integer, primary_key=True, index=True) 
    title = Column(String, index=True) 
    description = Column(String, index=True) 
    owner_id = Column(Integer, ForeignKey("users.id")) 
    owner = relationship("User", back_populates="items") 
