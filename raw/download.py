import requests
import json

def download_apk(package_name):
    url = f"https://f-droid.org/api/v1/packages/{package_name}"
    response = requests.get(url)
    if response.status_code == 200:
        data = json.loads(response.text)
        if "packageName" in data and "packages" in data:
            package = data["packages"][0]
            version_name = package["versionName"]
            version_code = package["versionCode"]
            apk_url = f"https://f-droid.org/repo/{package_name}_{version_code}.apk"
            apk_response = requests.get(apk_url)
            if apk_response.status_code == 200:
                with open(f"{package_name}_{version_name}.apk", "wb") as apk_file:
                    apk_file.write(apk_response.content)
                print(f"APK downloaded: {package_name}_{version_name}.apk")
            else:
                print(f"Failed to download APK: {apk_url}")
        else:
            print(f"No package information found for: {package_name}")
    else:
        print(f"Failed to fetch package information: {url}")

# Example usage
download_apk("org.fdroid.fdroid")
