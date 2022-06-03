import requests
import time
import click
import json
import uuid
import arrow 
import json
from json.decoder import JSONDecodeError
from nested_lookup import nested_lookup

@click.command()							

def main():
    """Open for read"""
    f = open('nvdcve-1.1-2022.json')
    data = json.load(f)

    vulns = []

    for item in data['CVE_Items']:
        cve_id = item["cve"]["CVE_data_meta"]["ID"]
        created_at = item["publishedDate"]
        updated_at = item["lastModifiedDate"]
        references = item["cve"]["references"]["reference_data"]
        summary = item["cve"]["description"]["description_data"][0]["value"]
        cvss2 = (
            item["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
            if "baseMetricV2" in item["impact"]
            else None
        )
        cvss3 = (
            item["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
            if "baseMetricV3" in item["impact"]
            else None
        )

        # Construct CWE and CPE lists
        cwes = get_cwes(
            item["cve"]["problemtype"]["problemtype_data"][0]["description"]
        )

        cpes = convert_cpes(item["configurations"])
        print(cpes)

        vulns.append({
            "cve_id":cve_id,
            "created_at":created_at,
            "updated_at":updated_at,
            "references":references,
            "summary":summary,
            "cvss2":cvss2,
            "cvss3":cvss3,
            "cwes":cwes,
            "cpes":cpes
        })
     
    # Closing file
    f.close()

    with open('data.json', 'w', encoding='utf-8') as f:
        json.dump(vulns, f, ensure_ascii=False, indent=4)

def get_uuid():
    return str(uuid.uuid4())    

def get_cwes(problems):
    """
    Takes a list of problems and return the CWEs ID.
    """
    return list(set([p["value"] for p in problems]))

def convert_cpes(conf):
    """
    This function takes an object, extracts its CPE uris and transforms them into
    a dictionnary representing the vendors with their associated products.
    """
    uris = nested_lookup("cpe23Uri", conf) if not isinstance(conf, list) else conf
    # print(uris)
    affected = []

    for uri in uris:
        # print(uri.split(":")[3:6])
        affectedVendors = uri.split(":")[3]
        # print(affectedVendors)
        affectedProducts = uri.split(":")[4]
        # print(affectedProducts)
        affectedProductVersion = uri.split(":")[5]
        # print(affectedProductVersion)

        affected.append({
            "vendor": affectedVendors,
            "product": affectedProducts,
            "version": affectedProductVersion,
        })

    return affected




if __name__ == '__main__':
    main()