import requests

def download_crx(extension_id):
    output_file="app/uploaded/"+output_file
    url = (
        "https://clients2.google.com/service/update2/crx?"
        "response=redirect&os=linux&arch=x86-64&os_arch=x86-64&nacl_arch=x86-64&"
        "prod=chromecrx&prodchannel=unknown&prodversion=9999.0.9999.0&"
        "acceptformat=crx2,crx3&x=id%3D" + extension_id + "%26uc"
    )

    print(f"Downloading CRX for extension ID: {extension_id}...")
    response = requests.get(url, allow_redirects=True)

    if response.status_code == 200:
        with open(output_file, "wb") as f:
            f.write(response.content)
        return extension_id
    return None


