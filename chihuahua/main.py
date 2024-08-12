"""
main.py
"""

import logging
from typing import Dict, Tuple, List
from datetime import datetime, timedelta
import re
from urllib import parse

from fastapi import FastAPI, Depends, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt
from jose.exceptions import JWTError, ExpiredSignatureError, JWTClaimsError
import bcrypt
from environs import Env
from databases import Database
from sqlalchemy import create_engine, text, inspect
from starlette.responses import RedirectResponse

# pylint: disable=import-error, relative-beyond-top-level, no-name-in-module
from . import schemas
from . import models
from .oauth2_password_bearer_cookie import OAuth2PasswordBearerOrCookie

from .exceptions import VerifyException

LOGGER = logging.getLogger(__name__)

# Reading config from environment variables
env = Env()

ACCESS_COOKIE_DOMAIN = env("ACCESS_COOKIE_DOMAIN")
ACCESS_COOKIE_NAME = env("ACCESS_COOKIE_NAME")
ACCESS_COOKIE_SECURE = env.bool("ACCESS_COOKIE_SECURE", False)
ACCESS_COOKIE_HTTPONLY = env.bool("ACCESS_COOKIE_HTTPONLY", True)
ACCESS_COOKIE_SAMESITE = env(
    "ACCESS_COOKIE_SAMESITE", "lax", validate=lambda s: s in ["lax", "strict", "none"]
)
ACCESS_TOKEN_EXPIRE_MINUTES = env.int("ACCESS_TOKEN_EXPIRE_MINUTES", 30)

JWT_TOKEN_SECRET = env("JWT_TOKEN_SECRET")

USER_DATABASE_URL = env("USER_DATABASE_URL")
ADMIN_USER_USERNAME = env("ADMIN_USERNAME", "admin")
ADMIN_USER_PASSWORD = env("ADMIN_USER_PASSWORD")
BASE_URL = env("BASE_URL")
REDIRECT_PATH = env("REDIRECT_PATH", "")

# Setting up app and other context
app = FastAPI(root_path=BASE_URL)

oauth2_scheme = OAuth2PasswordBearerOrCookie(
    tokenUrl="login", cookie_name=ACCESS_COOKIE_NAME
)


database = Database(USER_DATABASE_URL)


def hash_password(password):
    """Hash pasword"""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def check_password(password, hashed_password):
    "Check password against hashed password"
    return bcrypt.checkpw(password.encode("utf-8"), hashed_password.encode("utf-8"))


# Allows CORS if localhost
if ACCESS_COOKIE_DOMAIN == "localhost":
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["x-total-count"],
    )


# Exception Handlers
@app.exception_handler(VerifyException)
async def redirect_or_exception_handler(request: Request, exc: VerifyException):
    """Handle redirect or exception"""
    uri = request.headers.get("X-Forwarded-Uri", "")
    host = request.headers.get("X-Forwarded-Host", "")

    if "/api/" in uri:
        raise HTTPException(status_code=401, detail=exc.message)

    redirect_url = (
        "http://"
        + host
        + REDIRECT_PATH
        + "?url="
        + parse.quote("http://" + host + uri)
        + "&message="
        + parse.quote(exc.message)
    )
    return RedirectResponse(redirect_url)


# Dependencies


async def get_claims_from_bearer_token(
    token_tuple: Tuple[str, str] = Depends(oauth2_scheme)
) -> Tuple[dict, str]:
    """Get claims from bearer token"""
    _, token = token_tuple
    claims = None
    if token is None:
        message = "Login necessary"
    else:
        try:
            claims = jwt.decode(token, JWT_TOKEN_SECRET, algorithms=["HS256"])
            message = ""
        except ExpiredSignatureError:
            message = "Expired session"
        except JWTClaimsError:
            message = "Invalid claims"
        except JWTError:
            message = "Invalid token"
    return claims, message


# pylint: disable=broad-except
async def get_user_from_bearer_token(
    claims_tuple: Tuple[models.User, str] = Depends(get_claims_from_bearer_token),
) -> Tuple[models.User, str]:
    """Get User instance from bearer token"""
    claims, message = claims_tuple
    user = None
    if claims is not None:
        try:
            query = models.users.select().where(models.User.username == claims["sub"])
            user = models.User.from_record(await database.fetch_one(query))
        except Exception:
            pass
    return user, message


# pylint: enable=broad-except
async def verify_token(
    user_tuple: Tuple[models.User, str] = Depends(get_user_from_bearer_token)
):
    """Verify that the client provides a valid token"""
    user, message = user_tuple
    if not user:
        raise HTTPException(status_code=401, detail=message)


async def verify_token_admin(
    user_tuple: Tuple[models.User, str] = Depends(get_user_from_bearer_token)
):
    """Verify that the client provides a valid token and that the corresponding
    user is an administrator"""
    user, message = user_tuple
    if not user:
        raise HTTPException(status_code=401, detail=message)
    if not user.admin:
        raise HTTPException(status_code=401, detail="Unauthorized access")

# This line builds a dictionary with the column names as keys and their attributes from the models.py


@app.on_event("startup")
async def startup():
    """Run during startup of this application"""

    # Database engine setup
    engine = create_engine(USER_DATABASE_URL)

    # Inspector to check for table and columns
    inspector = inspect(engine)

    # Check if the 'users' table exists and has the correct columns
    user_table_exists = inspector.has_table("users")

    if user_table_exists:
        # Get the list of columns in the 'users' table
        existing_columns = {col['name'] for col in inspector.get_columns("users")}
        
        # Compare with the columns_dict derived from the User model
        columns_dict = {column.name: getattr(models.User, column.name) for column in models.User.__table__.columns}

        if not set(columns_dict.keys()).issubset(existing_columns):
            # If the existing table doesn't have the necessary columns, raise an error or handle accordingly
            raise Exception("The existing 'users' table does not have the necessary columns.")
    else:
        # If the 'users' table does not exist, create all tables
        models.Base.metadata.create_all(engine)

    # Connect with actual connection we will use from here on forwards
    await database.connect()

    # Create admin user
    query = models.users.select().where(models.User.username == ADMIN_USER_USERNAME)
    admin_user: models.User = await database.fetch_one(query)
    hashed_password = hash_password(ADMIN_USER_PASSWORD)

    if admin_user:
        query = (
            models.users.update()
            .where(models.User.username == ADMIN_USER_USERNAME)
            .values(hashed_password=hashed_password)
        )
        await database.execute(query)
    else:
        query = models.users.insert().values(
            username=ADMIN_USER_USERNAME,
            firstname="Administrator",
            lastname="Chihuahua",
            email="chihuahua@arriba.com.mx",
            admin=True,
            hashed_password=hashed_password,
        )
        await database.execute(query)


@app.on_event("shutdown")
async def shutdown():
    """Run during shutdown of this application"""
    await database.disconnect()


## JWT utility functions ##


def create_jwt_token(user: models.User, exp: timedelta = None) -> str:
    """Create a JSON Web Token (JWT) string from a User instance

    Args:
        user (User): The User instance,
        exp (timedelta, optional): Validity time in seconds. Defaults to None.

    Returns:
        str: A JSON Web Token
    """

    claims = {
        "sub": str(user.username),
        "iat": (now := datetime.utcnow()),
    }

    if exp:
        claims.update({"exp": now + exp})

    return jwt.encode(claims, JWT_TOKEN_SECRET, algorithm="HS256")


async def get_credentials(
    token_tuple: Tuple[str, str] = Depends(oauth2_scheme)
) -> Dict:
    """Get credentials"""

    # pylint: disable=raise-missing-from
    token_type, token = token_tuple

    if not token:
        return {
            "valid": False,
            "message": "Login necessary" if token_type == "cookie" else "Missing token",
            "claims": {},
            "token_type": token_type,
            "token": "",
        }

    try:
        claims = jwt.decode(token, JWT_TOKEN_SECRET, algorithms=["HS256"])
        message = ""
        valid = True
    except ExpiredSignatureError:
        claims = {}
        message = "Expired session"
        LOGGER.exception(message)
        valid = False
    except JWTClaimsError:
        claims = {}
        message = "Invalid claims"
        LOGGER.exception(message)
        valid = False
    except JWTError:
        message = "Invalid token"
        LOGGER.exception(message)
        claims = {}
        valid = False

    return {
        "valid": valid,
        "message": message,
        "claims": claims,
        "token_type": token_type,
        "token": token,
    }


async def get_user_from_claims(claims: Dict) -> models.User:
    """Fetch the User from the user database using the information provided in
    the decoded claims from a JWT token

    Args:
        claims (Dict): The claims as decoded from a JWT token

    Returns:
        User: A user instance
    """
    username = claims.get("username")
    query = models.users.select().where(models.User.username == username)
    return models.User.from_record(await database.fetch_one(query))


# *** Routes ****


@app.post("/login", response_model=schemas.Response)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Login a user"""

    username: str = form_data.username
    password: str = form_data.password

    # Query database
    query = models.users.select().where(models.User.username == username)
    record = await database.fetch_one(query)
    if not record:
        raise HTTPException(status_code=401, detail="Wrong username or password.")
    user = models.User.from_record(record)

    # Compare credentials
    if not check_password(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Wrong username or password.")

    # Create token
    jwt_token: str = create_jwt_token(
        user, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    # Create response with cookie
    response = JSONResponse(status_code=200, content={"success": True})

    # Cookie domain should not be used with localhost
    access_cookie_domain = (
        ACCESS_COOKIE_DOMAIN if "localhost" not in ACCESS_COOKIE_DOMAIN else None
    )

    # Set Cookie
    response.set_cookie(
        key=ACCESS_COOKIE_NAME,
        value=jwt_token,
        secure=ACCESS_COOKIE_SECURE,
        httponly=ACCESS_COOKIE_HTTPONLY,
        samesite=ACCESS_COOKIE_SAMESITE,
        domain=access_cookie_domain,
    )

    return response


@app.post(
    "/logout", dependencies=[Depends(verify_token)], response_model=schemas.Response
)
async def logout():
    """Logout user"""
    response = JSONResponse(status_code=200, content={"success": True})
    response.delete_cookie(ACCESS_COOKIE_NAME)
    return response


@app.get(
    "/me",
    response_model=schemas.UserOut,
    dependencies=[Depends(verify_token)],
)
async def get_me(
    user_tuple: Tuple[models.User, str] = Depends(get_user_from_bearer_token)
):
    """Get the details of the current user"""
    user, _ = user_tuple
    return user


def validate_paths_text_string(text_string: str) -> bool:
    """Validate that a text string containing paths"""
    if len(text_string) == 0:
        return True
    paths = text_string.split(",")
    for path in paths:
        if not re.match(r"/[a-z0-9/]+", path):
            return False
    return True


@app.get("/verify", response_model=schemas.Response)
async def verify_request(
    request: Request, user_tuple: Tuple[dict, str] = Depends(get_user_from_bearer_token)
):
    """Verify that the user has the permissions for the request"""

    uri = request.headers.get("X-Forwarded-Uri")
    host = request.headers.get("X-Forwarded-Host")

    if not host or not uri:
        msg = "Missing required X-Forwarded-Headers provided by Traefik"
        raise HTTPException(400, msg)

    # Get user
    user, message = user_tuple
    if not user:
        raise VerifyException(message)

    # Limit access to non-administrators
    if "admin" in uri and not user.admin:
        raise VerifyException("Unauthorized access")

    return JSONResponse(status_code=200, content={"success": True})


@app.get(
    "/users",
    response_model=List[schemas.UserOut],
    dependencies=[Depends(verify_token_admin)],
)
async def get_all_users(_end: int, _order: str, _sort: str, _start: int):
    """Get JSON Response with a list of all users in the database and
    a header continaing the total count."""
    query = (
        models.users.select().order_by(text(f"{_sort} {_order}")).slice(_start, _end)
    )
    user_records = [dict(user) for user in await database.fetch_all(query)]

    response = JSONResponse(user_records)
    response.headers["x-total-count"] = str(
        len(await database.fetch_all(models.users.select()))
    )
    return response


@app.get(
    "/users/{idx}",
    response_model=schemas.UserOut,
    dependencies=[Depends(verify_token_admin)],
)
async def get_user_by_id(idx: int):
    """Get user by its Id"""
    try:
        return models.User.from_record(
            await database.fetch_one(models.users.select().where(models.User.id == idx))
        )
    except Exception as exc:
        raise HTTPException(status_code=406, detail=str(exc)) from exc


@app.post(
    "/users",
    dependencies=[Depends(verify_token_admin)],
)
async def create_user(user: schemas.CreateUser):
    """Create user"""
    hashed_password = hash_password(user.password)

    try:
        await database.execute(
            models.users.insert().values(
                username=user.username.lower(),
                firstname=user.firstname,
                lastname=user.lastname,
                email=user.email,
                admin=user.admin,
                hashed_password=hashed_password,
                path_whitelist=user.path_whitelist,
                path_blacklist=user.path_blacklist,
                topic_whitelist=user.topic_whitelist,
                topic_blacklist=user.topic_blacklist,
            )
        )
        return JSONResponse(status_code=200, content={"success": True})
    except Exception as exc:
        raise HTTPException(
            status_code=406,
            detail=f"User with username '{user.username.lower()}' already exists",
        ) from exc


@app.put(
    "/users/{idx}",
    response_model=schemas.UserOut,
    dependencies=[Depends(verify_token_admin)],
)
async def modify_user(idx: int, modifications: schemas.ModifyUser):
    """Modify user"""
    mods = {k: v for k, v in modifications.__dict__.items() if v is not None}
    # If provided, hash the password
    if "password" in mods:
        mods["hashed_password"] = hash_password(modifications.password)
        del mods["password"]

    # Validate the paths_text_string
    for key in [
        "path_whitelist",
        "path_blacklist",
        "topic_whitelist",
        "topic_blacklist",
    ]:
        if key in mods:
            if not validate_paths_text_string(mods[key]):

                raise HTTPException(status_code=422, detail=f"Invalid value for {key}")

    # Update user in the database
    try:
        await database.execute(
            models.users.update().where(models.User.id == idx).values(**mods)
        )
    except Exception as exc:

        raise HTTPException(
            status_code=406, detail=f"User with id '{idx}' does not exist"
        ) from exc

    # Success
    return models.User.from_record(
        await database.fetch_one(models.users.select().where(models.User.id == idx))
    )


@app.delete(
    "/users/{idx}",
    dependencies=[
        Depends(verify_token_admin),
    ],
    response_model=schemas.Response,
)
async def delete_user(idx: int):
    """Delete user"""
    try:
        models.User.from_record(
            await database.fetch_one(models.users.select().where(models.User.id == idx))
        )
        await database.execute(models.users.delete().where(models.User.id == idx))
        return JSONResponse(status_code=200, content={"detail": "success"})
    except Exception as exc:
        raise HTTPException(
            status_code=406, detail=f"User with id '{idx}' does not exist"
        ) from exc
