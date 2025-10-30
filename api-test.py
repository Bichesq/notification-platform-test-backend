import requests

def test_list_applications():
    url = "http://localhost:8001/apps"  # Change to your backend URL if different
    params = {
        "skip": 0,
        "limit": 10
    }

    try:
        response = requests.get(url, params=params)
        print(f"Status Code: {response.status_code}")
        if response.status_code == 200:
            apps = response.json()
            print(f"Number of applications received: {len(apps)}")
            for app in apps:
                print(f"Application ID: {app['id']}, Name: {app['name']}")
        else:
            print(f"Error response: {response.text}")
    except Exception as e:
        print(f"Request failed: {e}")

if __name__ == "__main__":
    test_list_applications()
