from fastapi import Depends, FastAPI, HTTPException, status

from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer

from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession

from passlib.context import CryptContext
from uuid import uuid4
from jose import jwt, JWTError

from db import get_session, init_db
from models import Users, UserSignup, Token

from datetime import timedelta, datetime

# openssl rand -hex 32
SECRET_KEY = "d8e632e42229356dbbcd5fdc366a05e9bfaca0193ba016e4fd6cf03307d90241"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

SALT = "fa3e1b071f78d55d833c2df51a3089e5"

app = FastAPI()
templates = Jinja2Templates(directory="templates")
# 这里是 tokenUrl，而不是 token_url，是为了和 OAuth2 规范统一
# tokenUrl 是为了指定 OpenAPI 前端登录时的接口，在自己的程序中并无用处
# OAuthPasswordBearer 实现的功能很简单，只是把 Authorization Header 的 Bearer 取出来罢了
oauth2_bearer = OAuth2PasswordBearer(tokenUrl="token")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password + SALT, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def unauthorized_error(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail, headers={"WWW-Authenticate": "Bearer"})


def _create_token(data: dict, expires: timedelta = timedelta(minutes=15)) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + expires
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def _decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise unauthorized_error("Could not validate credentials")


async def get_user(email: str, session: AsyncSession = Depends(get_session)) -> Users:
    result = await session.execute(select(Users).where(Users.email == email))
    return result.scalar_one_or_none()

    # users = result.scalars().all()
    # return [Users(**user.__dict__) for user in users]


async def get_current_user(token: str = Depends(oauth2_bearer), session: AsyncSession = Depends(get_session)) -> Users:
    error = unauthorized_error("Could not validate credentials")
    payload = _decode_token(token=token)

    username = payload.get("sub")
    if not username:
        raise error
    expires = payload.get("exp")
    if expires < int(datetime.utcnow().timestamp()):
        raise unauthorized_error("Token expired")

    user = await get_user(username, session)
    if user is None:
        raise error
    return user


@app.on_event("startup")
async def on_startup():
    await init_db()


@app.post("/signup")
async def add_user(user: UserSignup, session: AsyncSession = Depends(get_session)):
    existed_user = await get_user(user.email, session)
    if existed_user is not None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email registered already")

    if not user.password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password invalid")

    new_user = Users(email=user.email, username=user.username, phone=user.phone,
        hashed_password=get_password_hash(user.password + SALT),
        id=str(uuid4())
    )

    session.add(new_user)
    await session.commit()
    await session.refresh(new_user)
    return "Signup success"


@app.post('/token', summary="Create access and refresh tokens for user", response_model=Token)
async def login(form: OAuth2PasswordRequestForm = Depends(), session: AsyncSession = Depends(get_session)):
    user = await get_user(form.username, session)
    if not user or not verify_password(form.password, user.hashed_password):
        raise unauthorized_error("Incorrect username or password")

    token = _create_token(data={"sub": form.username}, expires=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    response = {"access_token": token, "token_type": "bearer"}
    return response


@app.get("/private")
async def getPrivateEndPoint(current_user: Users = Depends(get_current_user)):
    user_data = current_user.__dict__
    user_data.pop("hashed_password")
    return user_data


@app.get("/")
async def root():
    return RedirectResponse(url="/docs")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="localhost", port=8004, reload=False)
