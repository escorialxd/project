import bcrypt 
from fastapi import FastAPI, HTTPException, Query 
from models import Base, User, UserUpdate  
from database import  engine, SessionLocal  
from pydantic import BaseModel, EmailStr  
from fastapi import Depends, HTTPException, status, FastAPI, Response 
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm 
from jose import JWTError, jwt 
from datetime import datetime, timedelta, timezone 
from sqlalchemy.orm import Session 
from typing import Optional 


Base.metadata.create_all(bind=engine)  
app = FastAPI()  
session = SessionLocal()  


SECRET_KEY = "your-secret-key" 
ALGORITHM = "HS256" 
ACCESS_TOKEN_EXPIRE_MINUTES = 15 


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login") 
pwd_context = bcrypt 


class UserCreateRequest(BaseModel):  
    email: EmailStr  
    password: str  
    name: str  
    surname: str  
    telephone_number: int  
class UserUpdate(BaseModel):  
    email: EmailStr  
    password: str  
    name: str  
    surname: str  
    telephone_number: int  


@app.get("/users") 
async def get_users( 
        name: str = None, 
        surname: str = None, 
        email: str = None, 
        telephone_number: str = None, 
        sort: str = Query(None, alias="sort"), 
        page: int = Query(1, ge=1), 
        limit: int = Query(10, le=100) 
): 
    query = session.query(User) 
    # Applying filters 
    if name: 
        query = query.filter(User.name.ilike(f"%{name}%")) 
    if surname: 
        query = query.filter(User.surname.ilike(f"%{surname}%")) 
    if email: 
        query = query.filter(User.email.ilike(f"%{email}%")) 
    if telephone_number: 
        query = query.filter(User.telephone_number.ilike(f"%{telephone_number}%")) 
    
    
    # Sorting 
    if sort: 
        if sort.lower() == 'asc': 
            query = query.order_by(User.name.asc()) 
        elif sort.lower() == 'desc': 
            query = query.order_by(User.name.desc()) 
    
    
    # Pagination 
    offset = (page - 1) * limit 
    query = query.offset(offset).limit(limit) 
    users = query.all() 
    return {"users": [user.to_dict() for user in users]} 


@app.get("/items/{item_id}")  
async def read_item(item_id):  
    return {"item_id": item_id}  


@app.get("/users/{user_id}")  
async def get_user(user_id: int):  
    user = session.query(User).filter(User.id == user_id).first()  
    if user:  
        return {"user": user.to_dict()}  
    raise HTTPException(status_code=404, detail="User not found")  


@app.post("/users")  
async def create_user(user: UserCreateRequest):  
    hashed_password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt()) 
    new_user = User(email=user.email, hashed_password=hashed_password, name = user.name, surname = user.surname, telephone_number = user.telephone_number)  
    session.add(new_user)  
    session.commit()  
    session.refresh(new_user)  
    return {"user": new_user.to_dict()}  


@app.patch("/users/{user_id}")  
async def update_user(user_id: int, user_update: UserUpdate):  
    user = session.query(User).filter(User.id == user_id).first()  
    if user:  
        user.email = user_update.email  
        user.hashed_password = bcrypt.hashpw(user_update.password.encode('utf-8'), bcrypt.gensalt()) 
        user.name = user_update.name  
        user.surname = user_update.surname  
        user.telephone_number = user_update.telephone_number  
        session.commit()  
        return {"user": user.to_dict()}  
    raise HTTPException(status_code=404, detail="User not found")  


@app.delete("/users/{user_id}")  
async def delete_user(user_id: int):  
    user = session.query(User).filter(User.id == user_id).first()  
    if user:  
        session.delete(user)  
        session.commit()  
        return {"message": "User deleted"}  
    raise HTTPException(status_code=404, detail="User not found")  


@app.post("/login") 
async def login(response: Response, form_data: OAuth2PasswordRequestForm = Depends()): 
    db = SessionLocal() 
    user = authenticate_user(db, form_data.username, form_data.password) 
    if not user: 
        raise HTTPException( 
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Incorrect email or password", 
            headers={"WWW-Authenticate": "Bearer"}, 
        ) 
    access_token = create_access_token( 
        data={"sub": user.email, "id": user.id}, 
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES) 
    ) 
    refresh_token = create_refresh_token({"sub": user.email, "id": user.id}) 
    response.set_cookie( 
        key="refresh_token", 
        value=refresh_token, 
        httponly=True,
        secure=True, 
        expires=datetime.now(timezone.utc) + timedelta(days=30), 
        # ... 
        samesite="strict" 
    ) 
    return {"access_token": access_token, "token_type": "bearer"} 


def verify_password(plain_password, hashed_password): 
    plain_password = plain_password.encode('utf-8') if isinstance(plain_password, str) else plain_password 
    hashed_password = hashed_password.encode('utf-8') if isinstance(hashed_password, str) else hashed_password 
    return bcrypt.checkpw(plain_password, hashed_password) 


def get_password_hash(password): 
    return bcrypt.hashpw(password, bcrypt.gensalt()) 


def authenticate_user(db: Session, email: str, password: str): 
    user = db.query(User).filter(User.email == email).first() 
    if not user: 
        return False 
    if not verify_password(password, user.hashed_password): 
        return False 
    return user 


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None): 
    to_encode = data.copy() 
    if expires_delta: 
        expire = datetime.utcnow() + expires_delta 
    else: 
        expire = datetime.utcnow() + timedelta(minutes=15) 
    to_encode.update({"exp": expire}) 
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM) 
    return encoded_jwt 


def create_refresh_token(data: dict): 
    encoded_jwt = jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM) 
    return encoded_jwt 


def get_current_user(token: str = Depends(oauth2_scheme)): 
    try: 
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM]) 
        email: str = payload.get("sub") 
        user_id: int = payload.get("id") 
        if email is None or user_id is None: 
            raise HTTPException( 
                status_code=status.HTTP_401_UNAUTHORIZED, 
                detail="Invalid authentication credentials", 
                headers={"WWW-Authenticate": "Bearer"}, 
            ) 
        return {"email": email, "user_id": user_id} 
    except JWTError: 
        raise HTTPException( 
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid authentication credentials", 
            headers={"WWW-Authenticate": "Bearer"}, 
        ) 