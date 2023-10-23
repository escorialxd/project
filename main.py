import logging
import os
from logging.handlers import TimedRotatingFileHandler
from fastapi import FastAPI, HTTPException, Query, Depends, status, Response, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from typing import Optional
from pydantic import BaseModel, EmailStr
from models import Base, User
from database import engine, SessionLocal
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext

Base.metadata.create_all(bind=engine)

app = FastAPI()


log_directory = 'logs'
if not os.path.exists(log_directory):
    os.makedirs(log_directory)


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


requests_handler = TimedRotatingFileHandler(f"logs/{datetime.now().strftime('%d.%m.%Y')}_request.json", when="midnight", backupCount=30)
requests_handler.setLevel(logging.INFO)
requests_handler.setFormatter(logging.Formatter('{"ip": "%(asctime)s %(message)s"}'))


errors_handler = TimedRotatingFileHandler(f"logs/{datetime.now().strftime('%d.%m.%Y')}_error.json", when="midnight", backupCount=30)
errors_handler.setLevel(logging.ERROR)
errors_handler.setFormatter(logging.Formatter('{"timestamp": "%(asctime)s", "message": "%(message)s"}'))


logger.addHandler(requests_handler)
logger.addHandler(errors_handler)


SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = 15


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


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

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def authenticate_user(db: Session, email: str, password: str):
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            return False
        if not verify_password(password, user.hashed_password):
            return False
        return user
    except Exception as e:
        logger.error(f"An exception occurred: {e}", exc_info=True)





def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    try:
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=15)
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt
    except Exception as e:
        logger.error(f"An exception occurred: {e}", exc_info=True)




def create_refresh_token(data: dict):
    encoded_jwt = jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt




async def get_current_user(token: str = Depends(oauth2_scheme)):
    try: 
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM]) 
        email: str = payload.get("sub") 
        user_id: int = payload.get("id") 
        if email is None or user_id is None:
            logger.error(f"An exception occurred: {e}", exc_info=True)
            raise HTTPException( 
                status_code=status.HTTP_401_UNAUTHORIZED, 
                detail="Invalid authentication credentials", 
                headers={"WWW-Authenticate": "Bearer"}, 
            ) 
        return {"email": email, "user_id": user_id} 
    except JWTError as e:
        logger.error(f"An exception occurred: {e}", exc_info=True)
        raise HTTPException( 
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid authentication credentials", 
            headers={"WWW-Authenticate": "Bearer"}, 
        ) 




@app.get("/users")
async def get_users(
        name: str = None,
        surname: str = None,
        email: str = None,
        telephone_number: str = None,
        sort: str = Query(None, alias="sort"),
        page: int = Query(1, ge=1),
        limit: int = Query(10, le=100),
        db: Session = Depends(get_db)
):
    try:
        query = db.query(User)
        # Applying filters
        if name:
            query = query.filter(User.name.ilike(f"%{name}%"))
        if surname:
            query = query.filter(User.surname.ilike(f"%{surname}%"))
        if email:
            query = query.filter(User.email.ilike(f"%{email}%"))
        if telephone_number:
            query = query.filter(User.telephone_number.ilike(f"%{telephone_number}%"))
        logger.info(f"Received a request to get users")
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
    except Exception as e:
        logger.error(f"An exception occurred: {e}", exc_info=True)




@app.get("/items/{item_id}")
async def read_item(item_id):
    return {"item_id": item_id}




@app.get("/users/{user_id}")
async def get_user(user_id: int, db: Session = Depends(get_db)):
    try:
        logger.info(f"Received a request to get user with id: {user_id}")
        user = db.query(User).filter(User.id == user_id).first()
        if user:
            return {"user": user.to_dict()}
        raise HTTPException(status_code=404, detail="User not found")
    except Exception as e:
        logger.error(f"An exception occurred: {e}", exc_info=True)




@app.post("/users")
async def create_user(user: UserCreateRequest, db: Session = Depends(get_db)):
    try:
        logger.request_handler("Received a request to create a new user")
        hashed_password = get_password_hash(user.password)
        new_user = User(email=user.email, hashed_password=hashed_password, name=user.name, surname=user.surname, telephone_number=user.telephone_number)
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        return {"user": new_user.to_dict()}
    except Exception as e:
        logger.error(f"An exception occurred: {e}", exc_info=True)




@app.patch("/users/{user_id}")
async def update_user(user_id: int, user_update: UserUpdate, db: Session = Depends(get_db)):
    try:
        logger.info(f"Received a request to update user with id: {user_id}")
        user = db.query(User).filter(User.id == user_id).first()
        if user:
            user.email = user_update.email
            user.hashed_password = pwd_context.hash(user_update.password)
            user.name = user_update.name
            user.surname = user_update.surname
            user.telephone_number = user_update.telephone_number
            db.commit()
            return {"user": user.to_dict()}
    except HTTPException(status_code=404, detail="User not found") as e:
        logger.error(f"An exception occurred: {e}", exc_info=True)
    raise



@app.delete("/users/{user_id}")
async def delete_user(user_id: int, db: Session = Depends(get_db)):
    try:
        logger.info(f"Received a request to delete user with id {user_id}")
        user = db.query(User).filter(User.id == user_id).first()
        if user:
            db.delete(user)
            db.commit()
            return {"message": "User deleted"}
    except HTTPException(status_code=404, detail="User not found") as e:
        logger.error(f"An exception occurred: {e}", exc_info=True)
    raise 




@app.post("/login")
async def login(response: Response, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db), request: Request = None):
    logger.info("Received a request to login")
    logger.info(f"Client IP: {request.client.host}")
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        logger.error(f"An exception occurred: {Exception}", exc_info=True)
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
        samesite="strict"
    )
    return {"access_token": access_token, "token_type": "bearer"}




@app.get("/secure-data")
async def get_secure_data(current_user: dict = Depends(get_current_user)):
    return {"message": "This is protected data", "user": current_user}



@app.middleware("http")
async def check_jwt_token(request: Request, call_next):
    token = request.headers.get('auth_token')

    if request.url.path in ["/", "/login", "/docs", "/openapi.json"]:
        return await call_next(request)

    if not token:
        logger.error(f"An exception occurred: {Exception}", exc_info=True)
        raise HTTPException(status_code=401, detail="Not token")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        logger.error(f"An exception occurred: {Exception}", exc_info=True)
        raise HTTPException(status_code=401, detail="Invalid token")

    response = await call_next(request)
    return response
