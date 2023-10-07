import datetime
from sqlalchemy.orm import Session
import jwt
from passlib.context import CryptContext
from jwt import PyJWTError
from fastapi import Depends, HTTPException, status, APIRouter
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from database import SessionLocal
from .models import UserModel
from datetime import datetime, timedelta
from .schemas import UserRegistration, User
from services import get_db

# app = FastAPI()
router = APIRouter()

SECRET_KEY = "5YDULM0AXTS67JG"
ACCESS_TOKEN_EXPIRE_MINUTE = 30
ALGORITHM = "HS256"
# Initialize Passlib's CryptContext for password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# configure OAuth2

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except PyJWTError:
        raise credentials_exception
    return username


@router.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    db = SessionLocal()
    user = db.query(UserModel).filter(UserModel.uid == form_data.username).first()
    db.close()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User Not Found",
            headers={"WWW-Authenticate": "Bearer"}
        )
    if not pwd_context.verify(form_data.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Wrong Password"
        )

    # Create a JWT token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTE)
    access_token = create_access_token(
        data={"sub": user.uid},
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token-type": "bearer"}


@router.get("/protected-route")
async def protected_route(currentuser: str = Depends(get_current_user)):
    return {"message": "This is a protected route", "user": currentuser}


@router.get("/get_user_details", response_model=User)
async def getUser(currentuser: str = Depends(get_current_user), db: Session = Depends(get_db)):
    user_detai = db.query(UserModel).filter(UserModel.uid == currentuser).first()
    db.close()
    # return {"user":currentuser}
    return user_detai


@router.post("/user_registration", response_model=User)
async def register_user(user_data: UserRegistration, db: Session = Depends(get_db)):
    hashed_password = get_password_hash(user_data.password)
    user_details = UserModel(uid=user_data.uid,
                             email=user_data.email,
                             fullname=user_data.fullname,
                             password=hashed_password)
    db.add(user_details)
    db.commit()
    db.refresh(user_details)
    return User(uid=user_details.uid,
                email=user_details.email,
                fullname=user_details.fullname)
