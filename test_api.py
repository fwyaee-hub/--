import requests
import sys

BASE_URL = 'http://127.0.0.1:5000/api'

def test_api():
    session = requests.Session()
    
    # 1. Login
    print("Testing Login...")
    login_payload = {'username': 'admin', 'password': 'admin'}
    response = session.post(f'{BASE_URL}/auth/login', json=login_payload)
    print(f"Login Status: {response.status_code}")
    print(f"Login Response: {response.text}")
    
    if response.status_code != 200:
        print("Login failed, aborting.")
        return

    # 2. Get Profile
    print("\nTesting Profile...")
    response = session.get(f'{BASE_URL}/users/profile')
    print(f"Profile Status: {response.status_code}")
    print(f"Profile Response: {response.text}")

    # 3. List Files
    print("\nTesting List Files...")
    response = session.get(f'{BASE_URL}/files/')
    print(f"List Files Status: {response.status_code}")
    print(f"List Files Response: {response.text}")

    # 4. Logout
    print("\nTesting Logout...")
    response = session.post(f'{BASE_URL}/auth/logout')
    print(f"Logout Status: {response.status_code}")
    print(f"Logout Response: {response.text}")

if __name__ == '__main__':
    try:
        test_api()
    except Exception as e:
        print(f"Error: {e}")
