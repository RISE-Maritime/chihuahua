"""
main.py
"""

from typing import Optional, Dict, Tuple
from urllib import parse
from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse
from starlette.responses import RedirectResponse
from contextlib import asynccontextmanager
from sqlalchemy import create_engine, inspect, MetaData, Table, func, text
from sqlalchemy.ext.declarative import declarative_base
from jose import jwt
from jose.exceptions import JWTError, ExpiredSignatureError, JWTClaimsError
from databases import Database
from databases.backends.postgres import Record
from passlib.context import CryptContext
from environs import Env
import logging
from logging.handlers import RotatingFileHandler
from .oauth2_password_bearer_cookie import OAuth2PasswordBearerOrCookie
from . import schemas
from .exceptions import VerifyException


# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Format
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

# Console output
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
console_handler.setFormatter(formatter)

# Log files
size_handler = RotatingFileHandler(
    "chihuahua.log", maxBytes=5 * 1024 * 1024, backupCount=3
)
size_handler.setLevel(logging.INFO)
size_handler.setFormatter(formatter)

# Add handlers to the logger
logger.addHandler(size_handler)
logger.addHandler(console_handler)


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
ADMIN_USER_ID = env("ADMIN_USER_ID", "admin")
ADMIN_USER_PASSWORD = env("ADMIN_USER_PASSWORD")
BASE_URL = env("BASE_URL")
REDIRECT_PATH = env("REDIRECT_PATH", "")

# Check JWT Token Secret
if len(JWT_TOKEN_SECRET) < 32:
    logging.error("JWT_TOKEN_SECRET must be at least 32 characters long.")
    SystemExit()

# SQLAlchemy base class
Base = declarative_base()

# Define the database connection using the databases package
database = Database(USER_DATABASE_URL)

# Separate SQLAlchemy engine for schema reflection
engine = create_engine(USER_DATABASE_URL)

# Global variables to hold the reflected users table and User class
users = None
User = None  # Declare User as a global variable

# Password hashing setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


async def check_password(email: str, password: str) -> bool:
    """Check password directly in the PostgreSQL database"""

    # Query to check if the password matches the hashed password stored in the database
    query = users.select().where(
        User.email == email, User.password == func.crypt(password, User.password)
    )
    result = await database.fetch_one(query)

    if result:
        logger.info(f"Succesfull login by {email}.")
        return True
    else:
        raise HTTPException(status_code=401, detail="Incorrect email or password.")


async def password_trigger_exists():
    query = text(
        """
        SELECT tgname, proname, prosrc
        FROM pg_trigger
        JOIN pg_proc ON pg_trigger.tgfoid = pg_proc.oid
        WHERE tgrelid = 'users'::regclass;
    """
    )
    triggers = await database.fetch_all(query)
    for trigger in triggers:
        trigger_name = trigger["tgname"]
        function_name = trigger["proname"]
        function_source = trigger["prosrc"]

        if "password" in function_source:
            logger.info(
                f"Found trigger '{trigger_name}' that calls function '{function_name}', which references column 'password' in 'users' table."
            )
            return True

    logger.info("No triggers referencing the 'password' column found.")
    return False


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Initiating startup ...")

    global users, User

    # Connect to the database
    await database.connect()
    logger.info("Successfully connected to the database.")

    # Check "Users" table existance and makeup
    inspector = inspect(engine)
    if "users" not in inspector.get_table_names():
        logger.info("Table 'Users' does not exist.")
        commands = [
            """
            CREATE TABLE users (
                id SERIAL PRIMARY KEY, 
                email TEXT NULL UNIQUE,            
                admin BOOLEAN DEFAULT FALSE,
                password TEXT NOT NULL,           
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
            """,
            """         
            -- Trigger function to update the last_updated column upon row modification
            CREATE OR REPLACE FUNCTION update_last_updated()
            RETURNS TRIGGER AS $$
            BEGIN
                NEW.last_updated = CURRENT_TIMESTAMP;
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql;
            """,
            """
            -- Triggers to update last_updated timestamps 
            CREATE TRIGGER trg_update_timestamp_users
            BEFORE UPDATE ON users
            FOR EACH ROW
            EXECUTE FUNCTION update_last_updated()
            """,
        ]
        for command in commands:
            await database.execute(command)
        logger.info("Created 'Users' table.")
    else:
        # Table exists, check that it has the required columns.
        query = text(
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name='users' AND column_name IN ('password', 'admin', 'email');
        """
        )
        result = await database.fetch_all(query)
        columns = {row["column_name"] for row in result}
        required_columns = {"password", "admin", "email"}
        if not required_columns.issubset(columns):
            missing = required_columns - columns
            message = f"Missing columns in 'users' table: {', '.join(missing)}"
            logger.error(message)
            SystemExit(message)
        logger.info("Table 'Users' exists as required.")

    # Check existance of a hashing password trigger
    if not await password_trigger_exists():
        commands = [
            """
            CREATE EXTENSION IF NOT EXISTS pgcrypto;
            """,
            """                  
            -- Create the password hashing function
            CREATE OR REPLACE FUNCTION hash_password_function()
            RETURNS TRIGGER AS $$
            BEGIN
                -- Hash the password using bcrypt
                NEW.password := crypt(NEW.password, gen_salt('bf'));
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql;
            """,
            """
            -- Create the trigger that calls the hashing function
            CREATE TRIGGER hash_password_trigger
            BEFORE INSERT OR UPDATE
            ON users
            FOR EACH ROW
            EXECUTE FUNCTION hash_password_function();
            """,
        ]
        for command in commands:
            await database.execute(command)
        logger.info(
            "Password hashing function 'hash_password_function' and associated trigger 'hash_password_trigger' created."
        )

    # Create a MetaData instance
    metadata = MetaData()

    # Reflect the 'users' table from the database
    users = Table("users", metadata, autoload_with=engine)

    # Dynamically map the table to the User class
    class User(Base):
        __table__ = users

        @classmethod
        def from_record(cls, record: Record):
            """Create a User instance from an asyncpg record

            Args:
                record (Record): AsyncPG record

            Returns:
                User: User instance
            """
            return cls(**dict(record))

        def to_dict(self):
            """Transform to dictionary"""
            dictionary = {}
            for column in self.__table__.columns:
                dictionary[column.name] = getattr(self, column.name)
            return dictionary

    # Assign the dynamically created User class to the global User variable
    globals()["User"] = User

    # Update or create admin user
    query = users.select().where(User.email == ADMIN_USER_ID)
    admin_user = await database.fetch_one(query)

    if admin_user:
        # Update admin user password if the user already exists
        logger.info(f"Admin user exists, updating password.")
        query = (
            users.update()
            .where(User.email == ADMIN_USER_ID)
            .values(password=ADMIN_USER_PASSWORD)
        )
        await database.execute(query)
    else:
        # Insert new admin user if not exists
        logger.info(f"Admin user does not exist, creating.")
        query = users.insert().values(
            email=ADMIN_USER_ID,
            admin=True,
            password=ADMIN_USER_PASSWORD,
        )
        await database.execute(query)

    logger.info(f"Startup completed successfully.")
    yield
    await database.disconnect()
    logger.info(f"Successfully disconnected from the database.")


# Initialize FastAPI app
app = FastAPI(root_path=BASE_URL, lifespan=lifespan)

oauth2_scheme = OAuth2PasswordBearerOrCookie(
    tokenUrl="login", cookie_name=ACCESS_COOKIE_NAME
)

# Allows CORS if localhost
if ACCESS_COOKIE_DOMAIN == "localhost":
    logger.info("Enabling CORS in 'localhost'.")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["x-total-count"],
    )

# TOKEN VERIFICATION FUNCTIONS


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
            logger.info(f"Received claims: {claims}")
            message = ""
        except ExpiredSignatureError:
            message = "Expired session"
        except JWTClaimsError:
            message = "Invalid claims"
        except JWTError:
            message = "Invalid token"
    return claims, message


async def get_user_from_bearer_token(
    claims_tuple: Tuple[Optional[Dict], str] = Depends(get_claims_from_bearer_token),
) -> Tuple[Optional[User], str]:
    """Get User instance from bearer token"""
    claims, message = claims_tuple
    user = None
    if claims is not None:
        try:
            query = users.select().where(User.email == claims["sub"])
            user = User.from_record(await database.fetch_one(query))
        except Exception as e:
            logger.error(f"Error fetching user from database: {e}")
            message = "User does not exist."
            pass
    return user, message


async def verify_token(
    user_tuple: Tuple[Optional[User], str] = Depends(get_user_from_bearer_token)
):
    """Verify that the client provides a valid token"""
    user, message = user_tuple
    if not user:
        raise HTTPException(status_code=401, detail=message)


async def verify_token_admin(
    user_tuple: Tuple[Optional[User], str] = Depends(get_user_from_bearer_token)
):
    """Verify that the client provides a valid token and that the corresponding
    user is an administrator"""
    user, message = user_tuple
    if not user:
        raise HTTPException(status_code=401, detail=message)
    if not user.admin:
        raise HTTPException(status_code=401, detail="Unauthorized access")


def create_jwt_token(user: User, exp: timedelta) -> str:
    """Create a JSON Web Token (JWT) string"""
    # Role used by PostgREST
    role = "admin_user" if user.admin else "normal_user"

    claims = {
        "sub": str(user.email),
        "exp": int((datetime.now() + exp).timestamp()),
        "role": role,
    }
    logger.info(f"Claims created: {claims}")
    return jwt.encode(claims, JWT_TOKEN_SECRET, algorithm="HS256")


# ROUTES


@app.post("/login", response_model=schemas.Response)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Login a user"""

    email: str = form_data.username
    password: str = form_data.password

    logger.info(f"Login attempt by {email}.")

    # Query database
    query = users.select().where(User.email == email)
    record = await database.fetch_one(query)
    if not record:
        raise HTTPException(status_code=401, detail="Wrong email or password.")
    user = User.from_record(record)

    # Compare credentials
    if not await check_password(email, password):
        raise HTTPException(status_code=401, detail="Wrong email or password.")
    logger.info(f"Correct password by {email}.")

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


@app.get(
    "/me",
    dependencies=[Depends(verify_token)],
)
async def get_me(
    user_tuple: Tuple[Optional[User], str] = Depends(get_user_from_bearer_token)
):
    """Get the details of the current user"""
    user, _ = user_tuple
    return user


@app.get("/verify", response_model=schemas.Response)
async def verify_request(
    request: Request,
    user_tuple: Tuple[Optional[User], str] = Depends(get_user_from_bearer_token),
):
    """Verify that the user has the permissions for the request"""

    uri = request.headers.get("X-Forwarded-Uri")
    host = request.headers.get("X-Forwarded-Host")

    if not host or not uri:
        message = "Missing required X-Forwarded-Headers provided by Traefik"
        raise HTTPException(status_code=400, detail=message)

    # Get user
    user, message = user_tuple
    if not user:
        raise VerifyException(message)

    # Limit access to non-administrators
    if "admin" in uri and not user.admin:
        raise VerifyException("Unauthorized access")

    return JSONResponse(status_code=200, content={"success": True})


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
