# from config import User
# import pytest
# from fastapi.testclient import TestClient
# from main import app
# from db import get_db
# from utils import verify_password

# client = TestClient(app)


# @pytest.fixture(scope="module")
# def db():
#     # Setup
#     db = get_db()
#     yield db
#     # Teardown
#     db.close()


# def test_get_students(db):
#     # Make a GET request to /students/all
#     response = client.get("/students/all")
#     assert response.status_code == 200
#     assert isinstance(response.json(), list)


# def test_signup(db):
#     # Make a POST request to /students/ with valid student data
#     student_data = {
#         "fname": "ganesh",
#         "lname": "poloju",
#         "email": "ganesh@example.com",
#         "password": "123456789",
#     }
#     response = client.post("/students/", json=student_data)
#     assert response.status_code == 200
#     assert response.json()["message"] == "User created successfully"

#     # Verify that the user is added to the database
#     user = db.query(User).filter(User.email == "johndoe@example.com").first()
#     assert user is not None


# def test_login(db):
#     # Make a POST request to /login with valid login credentials
#     login_data = {
#         "username": "ganesh@gmail.com",
#         "password": "123456789",
#     }
#     response = client.post("/login", data=login_data)
#     assert response.status_code == 200
#     assert "access_token" in response.json()
#     assert "refresh_token" in response.json()


# def test_get_students_authenticated(db):
#     # Make a GET request to /students/all/in with authentication headers
#     token = "..."  # Replace with a valid access token
#     headers = {"Authorization": f"Bearer {token}"}
#     response = client.get("/students/all/in", headers=headers)
#     assert response.status_code == 200
#     assert isinstance(response.json(), list)


# def test_change_password(db):
#     # Make a POST request to /changepassword with valid password change data
#     password_data = {
#         "email": "ganesh@gmail.com",
#         "old_password": "123456789",
#         "new_password": "987654321",
#     }
#     response = client.post("/changepassword", json=password_data)
#     assert response.status_code == 200
#     assert response.json()["message"] == "Password changed successfully"

#     # Verify that the password is updated in the database
#     user = db.query(User).filter(User.email == "johndoe@example.com").first()
#     assert user is not None
#     assert verify_password("newpassword123", user.password)


# def test_get_students_unauthenticated(db):
#     # Make a GET request to /students/all/in without authentication headers
#     response = client.get("/students/all/in")
#     assert response.status_code == 401
#     assert response.json()["detail"] == "Not authenticated"


# def test_invalid_login_credentials(db):
#     # Make a POST request to /login with invalid login credentials
#     login_data = {
#         "username": "johndoe@example.com",
#         "password": "invalidpassword",
#     }
#     response = client.post("/login", data=login_data)
#     assert response.status_code == 400
#     assert response.json()["detail"] == "Incorrect password"


# def test_existing_email_signup(db):
#     # Make a POST request to /students/ with an existing email
#     student_data = {
#         "fname": "Jane",
#         "lname": "Doe",
#         "email": "johndoe@example.com",  # Existing email from previous test
#         "password": "password123",
#     }
#     response = client.post("/students/", json=student_data)
#     assert response.status_code == 200
#     assert response.json()["message"] == "Email already exists"


# def test_invalid_password_change(db):
#     # Make a POST request to /changepassword with invalid password change data
#     password_data = {
#         "email": "johndoe@example.com",
#         "old_password": "invalidpassword",
#         "new_password": "newpassword123",
#     }
#     response = client.post("/changepassword", json=password_data)
#     assert response.status_code == 400
#     assert response.json()["detail"] == "User not found"
