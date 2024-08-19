import requests
from random import randint

random_email = f"foo-{randint(0,1000)}@hotmail.com"


def test_access_to_api_denied():
    # Denied access without JWT
    response = requests.get("http://localhost/api/users")
    assert response.status_code == 401


def test_access_to_api_granted_to_admin_user():
    response = requests.post(
        "http://localhost/auth/api/login", {"username": "admin", "password": "password"}
    )
    assert response.status_code == 200
    cookies = response.cookies
    print(cookies.get_dict()["chihuahua-access"])

    response = requests.get(
        "http://localhost/api/users",
        headers={
            "Authorization": f"Bearer {cookies.get_dict()['chihuahua-access']}",
        },
    )
    assert response.status_code == 200


def test_admin_user_can_create_users():
    response = requests.post(
        "http://localhost/auth/api/login", {"username": "admin", "password": "password"}
    )
    assert response.status_code == 200
    cookies = response.cookies

    response = requests.post(
        "http://localhost/api/users",
        json={
            "password": "password",
            "email": random_email,
            "admin": False,
        },
        headers={
            "Authorization": f"Bearer {cookies.get_dict()['chihuahua-access']}",
        },
    )
    print(response.content)
    assert response.status_code == 201


def test_admin_user_can_add_rows_to_non_user_tables():
    response = requests.post(
        "http://localhost/auth/api/login", {"username": "admin", "password": "password"}
    )
    assert response.status_code == 200
    cookies = response.cookies

    response = requests.post(
        "http://localhost/api/comments",
        json={
            "text": "test",
        },
        headers={
            "Authorization": f"Bearer {cookies.get_dict()['chihuahua-access']}",
        },
    )
    assert response.status_code == 201


def test_normal_user_can_add_rows_to_non_user_tables():
    response = requests.post(
        "http://localhost/auth/api/login",
        {"username": random_email, "password": "password"},
    )
    assert response.status_code == 200
    cookies = response.cookies

    response = requests.post(
        "http://localhost/api/comments",
        json={
            "text": "test",
        },
        headers={
            "Authorization": f"Bearer {cookies.get_dict()['chihuahua-access']}",
        },
    )
    assert response.status_code == 201


def test_normal_user_cannot_create_users():
    response = requests.post(
        "http://localhost/auth/api/login",
        {"username": random_email, "password": "password"},
    )
    assert response.status_code == 200
    cookies = response.cookies

    response = requests.post(
        "http://localhost/api/users",
        json={
            "password": "password",
            "email": "foo-" + random_email,
            "admin": False,
        },
        headers={
            "Authorization": f"Bearer {cookies.get_dict()['chihuahua-access']}",
        },
    )
    assert response.status_code == 403


def test_admin_user_can_read_users_without_restrictions():
    response = requests.post(
        "http://localhost/auth/api/login",
        {"username": "admin", "password": "password"},
    )
    assert response.status_code == 200
    cookies = response.cookies

    response = requests.get(
        f"http://localhost/api/users",
        headers={
            "Authorization": f"Bearer {cookies.get_dict()['chihuahua-access']}",
        },
    )
    assert response.status_code == 200
    assert "password" in response.json()[0]
    assert "admin" in response.json()[0]


# def test_normal_user_can_update_its_record_with_restrictions():
#     response = requests.post(
#         "http://localhost/auth/api/login",
#         {"username": random_email, "password": "password"},
#     )
#     assert response.status_code == 200
#     cookies = response.cookies

#     response = requests.patch(
#         f"http://localhost/api/users?email=eq.{random_email}",
#         headers={
#             "Authorization": f"Bearer {cookies.get_dict()['chihuahua-access']}",
#         },
#         json={"password": "foobar"},
#     )
#     print(response.status_code)
#     print(response.content)
#     assert response.status_code == 200

# response = requests.post(
#     "http://localhost/api/rpc/get_jwt_claims",
#     headers={
#         "Authorization": f"Bearer {cookies.get_dict()['chihuahua-access']}",
#     },
# )
# print(response.content)

# response = requests.post(
#     "http://localhost/auth/api/login",
#     {"username": random_email, "password": "foobar"},
# )
# assert response.status_code == 200
# cookies = response.cookies


def test_normal_user_can_read_users_without_restrictions():
    response = requests.post(
        "http://localhost/auth/api/login",
        {"username": random_email, "password": "password"},
    )
    assert response.status_code == 200
    cookies = response.cookies

    response = requests.get(
        f"http://localhost/api/users",
        headers={
            "Authorization": f"Bearer {cookies.get_dict()['chihuahua-access']}",
        },
    )
    assert response.status_code == 200
