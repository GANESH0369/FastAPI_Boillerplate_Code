from config import SessionLocal, User, get_db
from db import LoginRequest, StudentCreate
from fastapi import Depends, FastAPI, Response
from sqlalchemy.orm import Session
from sqlalchemy.ext.declarative import declarative_base
import bcrypt
from fastapi import FastAPI, status, HTTPException, Depends
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.security import HTTPBasicCredentials
from db import StudentCreate,TokenSchema
from db import StudentCreate
from deps import get_current_user
from utils import blacklist_token, create_access_token,create_refresh_token, get_hashed_password, verify_password
from utils import JWT_SECRET_KEY,ALGORITHM
from db import ChangePasswordSchema




from logging.config import dictConfig
import logging
from loggers import LogConfig

dictConfig(LogConfig().dict())
logger = logging.getLogger("mycoolapp")
app = FastAPI()



# get all user 
@app.get("/students/all")
def get_students(db: Session = Depends(get_db)):
    try:
        students = db.query(User).all()
        logger.info("details fetched successfully")
        return students
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
        return {"error": "Internal server error"}

# sign up user details
@app.post("/students/")
def signup(student: StudentCreate, db: Session = Depends(get_db)):
    try:
        existing_user = db.query(User).filter(User.email == student.email).first()
        if existing_user:
            logger.warning("exist email Warning")
            return {"message": "Email already exists"}
        
        # encrypted_password = hashpw(student.password.encode('utf-8'), gensalt())
        hashed_password=get_hashed_password(student.password)
        new_user = User(lname=student.lname, fname=student.fname, email=student.email, password=hashed_password)
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        logger.info("User created successfully")
        return {"message": "User created successfully"}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))



#login function for users


# @app.post('/login', response_model=TokenSchema)
# def login(request: LoginRequest, db: Session = Depends(get_db)):
#     try:
#         user = db.query(User).filter(User.email == request.username).first()
#         if user is None:
#             raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect email")
#         hashed_pass = user.password
#         if not verify_password(request.password, hashed_pass):
#             logger.error("Incorrect password")
#             raise HTTPException(
#                 status_code=status.HTTP_400_BAD_REQUEST,
#                 detail="Incorrect password"
#             )
#         logger.info("token get successfully")
#         return {
#             "access_token": create_access_token(user.email),
#             "refresh_token": create_refresh_token(user.email),
#         }
#     except Exception as e:
#         logger.error(f"An error occurred: {str(e)}")
#         raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="internal server error")

@app.post('/login', response_model=TokenSchema)
def login(request: LoginRequest, db: Session = Depends(get_db)):
    try:
        user = db.query(User).filter(User.email == request.username).first()
        if user is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect email")
        
        hashed_pass = user.password
        if not verify_password(request.password, hashed_pass):
            logger.error("Incorrect password")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Incorrect password"
            )
        
        logger.info("Token generated successfully")
        return {
            "access_token": create_access_token(user.email),
            "refresh_token": create_refresh_token(user.email),
        }
    
    except HTTPException as http_exception:
        raise http_exception
    
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")



# get user based on token concept
@app.get("/students/all/in")
def get_students(skip: int = 0, limit: int = 100, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        students = db.query(User).offset(skip).limit(limit).all()
        logger.info("successfully done ")
        return students
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An error occurred while fetching students")



@app.post("/changepassword")
def change_password(request: ChangePasswordSchema, db: Session = Depends(get_db)):
    try:
        # import pdb;pdb.set_trace()
        user = db.query(User).filter(User.email == request.email).first()
        if user is None:
            logger.error("Dummy Error")
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User not found")
        
        if not verify_password(request.old_password, user.password):
            # return {"message": "Invalid password"}
            logger.error("Dummy Error")
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User not found")
        encrypted_password = get_hashed_password(request.new_password)
        user.password = encrypted_password
        db.commit()
        logger.info("Dummy Info")
        return {"message": "Password changed successfully"}
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An error occurred while changing password")



from deps import TOKEN_MANAGER

@app.post("/api/logout")
async def logout(token: str = Depends(TOKEN_MANAGER), db: SessionLocal = Depends(get_db)):
    blacklist_token(db, token)
    return {"response": "Logged out"}
