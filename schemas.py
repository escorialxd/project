from typing import Union, Optional
from pydantic import BaseModel 


class ItemBase(BaseModel): 
    title: str 
    description: Union[str, None] = None 


class ItemCreate(ItemBase): 
    pass 


class Item(ItemBase): 
    id: int 
    owner_id: int 
    class Config: 
        orm_mode = True 


class UserBase(BaseModel): 
    email: str 


class UserCreate(UserBase): 
    password: str 
    name: str 
    surname: str 
    telephone_number: int 

    
class User(UserBase): 
    id: int 
    is_active: bool 
    name : str 
    surname = str 
    telephone_number = int 
    items: list[Item] = [] 
    class Config: 
        orm_mode = True 


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    email: str
    exp: Optional[int] = None
