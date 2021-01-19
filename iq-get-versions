
import requests
import json
import urllib

def pp(page):
    print(json.dumps(page, indent=4))

def print_results(results, file_name = "results_1.json"):
	with open(file_name, "w+") as file:
		file.write(json.dumps(results, indent=4))
	print(f"Json results saved to -> {file_name}")

def get_url(url):
	return iq_session.get(url).json()

def get_versions(publicId, component):
	params = urllib.parse.urlencode(component).replace("%27", "%22")
	url = f"{iq_url}/rest/ci/componentDetails/application/{publicId}/allVersions?{params}"
	return get_url(url)

def version(c):
	return c['componentIdentifier']['coordinates']['version']

iq_session = requests.Session()
iq_session.auth = requests.auth.HTTPBasicAuth("admin", "admin123")
iq_session.cookies.set('CLM-CSRF-TOKEN', 'api')
iq_headers = {'X-CSRF-TOKEN': 'api'}
iq_url = "http://localhost:8070"

publicId = "sandbox-application"

component = {
            "componentIdentifier": {
                "format": "a-name",
                "coordinates": {
                    "name": "org.webjars angularjs",
                    "qualifier": "",
                    "version": "1.2.16"
                }
            }
        }

data = get_versions(publicId, component)
print_results(data)

#---- Example of finding the version with the lowest security threat. 
current_version = version(component)
current_threat = 0
least_version = ""
least_threat = 0

for d in data["allVersions"]:
	this_version = version(d)
	threat = 0
	if this_version >= current_version:
		for p in d["policyAlerts"]:
			if "security" in p['trigger']['policyName'].lower():
				threat += p['trigger']['threatLevel']

		if this_version == current_version:
			current_threat = threat
			least_threat = threat
			least_version = current_version

		if threat <= least_threat:
			least_version = this_version
			least_threat = threat

print(current_version, current_threat, least_version, least_threat)
#-----
