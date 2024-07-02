import requests
from urllib.parse import urlparse, parse_qs


def parse_url(url):
    parsed_url = urlparse(url)
    query_string = parsed_url.query
    return parse_qs(query_string)


def test_access_and_authentication():
    # An attempt to access a resource that is not accessible without authentication
    # results in rediraction to <host>/auth with two parameters in the url:
    # 'message' indicating the reason and 'url' indicating the originally requested
    # url
    response = requests.get("http://localhost/whoami")
    assert response.status_code == 200
    params = parse_url(response.url)
    assert response.url.split("?")[0] == "http://localhost/auth"
    assert params["url"][0] == "http://localhost/whoami"
    assert params["message"][0] == "Login necessary"

    # A login request with non-existing username ...
    response = requests.post(
        "http://localhost/auth/api/login", {"username": "foo", "password": "foo"}
    )

    # ... returns a status code HTTPError:401 Unauthorized
    assert response.status_code == 401

    # A login request with wrong password ...
    response = requests.post(
        "http://localhost/auth/api/login", {"username": "admin", "password": "foo"}
    )

    # ... returns a status code HTTPError:401 Unauthorized
    assert response.status_code == 401

    # A login request with the right credentials ...
    response = requests.post(
        "http://localhost/auth/api/login", {"username": "admin", "password": "password"}
    )

    # ... returns a status code 200:OK ...
    assert response.status_code == 200

    # ... and returns a cookie containing the bearer token
    cookies = response.cookies
    assert "chihuahua-access" in cookies.get_dict()

    # Protected resources are accessible with the cookie ...
    response = requests.get("http://localhost/whoami", cookies=cookies)
    assert response.status_code == 200
    assert len(response.history) == 0

    # ... or by providing the bearer token in the request headers
    response = requests.get(
        "http://localhost/whoami",
        headers={
            "Authorization": f"Bearer {cookies.get_dict()['chihuahua-access']}",
        },
    )
    assert response.status_code == 200
    assert len(response.history) == 0
