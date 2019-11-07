#! /bin/bash

filename="highvuln_repo-micr_fixavailable.out"
host="http://console-url:port"
registryName="micr"
user="administrator"
pass="password"
severity="high"

#gets you the ID of the CVEs & prints them
curl -X GET -s -u $user:$pass ''$host'/api/v2/risks/vulnerabilities?include_vpatch_info=true&show_negligible=false&page=1&pagesize=50&skip_count=true&severity='$severity'&registry_name='$registryName'&fix_availability=true' | jq -r '.result[] | "\(.name)"' > highvuln_repo-micr_fixavailable.out
echo "cve-got"
#count=$(curl -X GET -s -u $user:$pass ''$host'/api/v2/risks/vulnerabilities?include_vpatch_info=true&show_negligible=false&page=1&pagesize=50&skip_count=false&severity='$severity'&registry_name='$registryName'&fix_availability=true' | jq -r '.count')

#EXAMPLE
#curl -X GET -s -u $user:$pass 'http://10.146.0.125/api/v2/risks/vulnerabilities?include_vpatch_info=true&show_negligible=false&page=1&pagesize=50&skip_count=true&severity='$severity'&registry_name='$registryName'&fix_availability=true' | jq -r '.result[] | "\(.name)"' > highvuln_repo-micr_fixavailable.out
#CVE-2015-2806
#CVE-2019-5481
#CVE-2019-5482


#gets you the repoNames
curl -X GET -s -u $user:$pass ''$host'/api/v2/risks/vulnerabilities?include_vpatch_info=true&show_negligible=false&page=1&pagesize=50&skip_count=false&severity='$severity'&registry_name='$registryName'&fix_availability=true' | jq -r '.result[] | "\(.image_repository_name)"' > repo_name.out
echo "repo-got"
#gets you the imageNames
curl -X GET -s -u $user:$pass ''$host'/api/v2/risks/vulnerabilities?include_vpatch_info=true&show_negligible=false&page=1&pagesize=50&skip_count=false&severity='$severity'&registry_name='$registryName'&fix_availability=true' | jq -r '.result[] | "\(.image_name)"' > image_name.out
echo "image-got"

#gets you the resource
curl -X GET -s -u $user:$pass ''$host'/api/v2/risks/vulnerabilities?include_vpatch_info=true&show_negligible=false&page=1&pagesize=50&skip_count=false&severity='$severity'&registry_name='$registryName'&fix_availability=true' | jq -r '.result[] | "\(.resource)" | "\(.type)"' > resource_type.out
echo "type-got"

#gets you the resourceName
curl -X GET -s -u $user:$pass ''$host'/api/v2/risks/vulnerabilities?include_vpatch_info=true&show_negligible=false&page=1&pagesize=50&skip_count=false&severity='$severity'&registry_name='$registryName'&fix_availability=true' | jq -r '.result[] | "\(.resource)" | "\(.name)"' > resource_name.out
echo "name-got"

#nested while loop to take the above information and modify the body for the next API call
while IFS= read -r CVE
do
	echo $CVE
	while IFS= read -r repo_name
	do
		_repo_name=$(echo $repo_name | tr / %2f)
		echo $_repo_name
		while IFS= read -r image_name
		do
			_image_name=$(echo $image_name | tr / %2f)
			echo $_image_name

			while IFS= read -r resource_type
			do
				echo $resource_type
				while IFS= read -r resource_name
					do
						echo $resource_name
						curl -X GET -u $user:$pass ''$host'/api/v2/heuristics?cve='$CVE'&repo_name='$repo_name'&image_name='$image_name'&resource_type='$resource_type'&registry='$registryName'&resource_name='$resource_name'' > policyget.out

						sed '2d' policyget.out && sed '5d' policyget.out && sed '9,20d' policyget.out
						sed '$i","' policyget.out
						sed '$i"vuln_id": 0,' policyget.out
						sed '$i"repo_id": 0,' policyget.out
						sed '$i"heuristic_ref_id": 0,' policyget.out
						sed '$i"image_id": 0,' policyget.out
						sed '$i"is_auto_generated": true,' policyget.out
						sed '$i"created": "0001-01-01T00:00:00Z",' policyget.out
						sed '$i"updated": "0001-01-01T00:00:00Z",' policyget.out
						sed '$i"audit_count": 0,' policyget.out
						sed '$i "enforce_after_days": 0,' policyget.out
						sed '$i"enforce_scheduler_added_on": 0,' policyget.out
						sed '$i"is_audit_checked": false,' policyget.out
						sed '$i"image_name": '$_image_name',' policyget.out
						sed '$i"repo_name": '$_repo_name',' policyget.out
						sed '$i"cve": '$CVE',' policyget.out
						sed '$i"resource_type": '$resource_type',' policyget.out
						sed '$i"resource_name": '$resource_name',' policyget.out
						sed '$i"vpatch_version": "V1",' policyget.out
						sed '$i"audit_on_failure": true,' policyget.out
						sed '$i"fail_cicd": true,' policyget.out
						sed '$i"block_failed": true,' policyget.out
						sed '$i"domain_name": "",' policyget.out
						sed '$i"domain": ""' policyget.out

						curl -X POST -u $user:$pass ''$host'/api/v2/runtime_policies' --data-binary "@policyget.out"

				done < resource_name.out
			done < resource_type.out
		done < image_name.out
	done < repo_name.out
done < $filename
