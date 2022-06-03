import requests
import time
import click
import json

from json.decoder import JSONDecodeError

def __get(product, keyword, limit, key, verbose):
    """Calculate required pages for multiple requests, send the GET request with the search criteria, return list of CVEs or CPEs objects."""

    # NIST 6 second rate limit recommendation on requests without API key
    if key:
        delay = 0.6
    else:
        delay = 6 

    # Get the default 20 items to see the totalResults and determine pages required.
    if product == 'cve':
        link = 'https://services.nvd.nist.gov/rest/json/cves/1.0?'
    elif product == 'cpe':
        link = 'https://services.nvd.nist.gov/rest/json/cpes/1.0?'
    else:
        raise ValueError('Unknown Product')
    
    parameters = {
        'cpe_dict': 'True',
        'keyword': keyword
    }

    # 'pubStartDate' : '2021-08-04T13:00:00:000 UTC%2B01:00'
    # 'pubEndDate' : '2021-07-01T13:00:00:000 UTC%2B01:00'

    # if verbose:
    #     print('Filter:\n' + link)
    #     print(parameters)

    raw = requests.get(link, params=parameters, timeout=10)
    

    try: # Try to convert the request to JSON. If it is not JSON, then print the response and exit.
        raw = raw.json() 
        if 'message' in raw:
            raise LookupError(raw['message'])
    except JSONDecodeError:
        print('Invalid search criteria syntax: ' + str(raw))
        print('Attempted search criteria: ' + parameters)
        exit()
    
    time.sleep(delay) 
    totalResults = raw['totalResults']

    # If a limit is in the search criteria or the total number of results are less than or equal to the default 20 that were just requested, return and don't request anymore.
    if limit or totalResults <= 20:
        return raw

    # If the total results is less than the API limit (Should be 5k but tests shows me 2k), just grab all the results at once.
    elif totalResults > 20 and totalResults < 2000:
        parameters['resultsPerPage'] = str(totalResults)
        raw = requests.get(link, params=parameters, timeout=10).json()
        return raw

    # If the results is more than the API limit, figure out how many pages there are and calculate the number of requests.
    # Send a request starting at startIndex = 0, then get the next page and ask for 2000 more results at the 2000th index result until all results have been grabbed.
    # Add each ['CVE_Items'] list from each page to the end of the first request. Effectively creates one data point.
    elif totalResults > 2000:
        pages = (totalResults // 2000) + 1
        startIndex = 0
        rawTemp = []
        if product == 'cve':
            for eachPage in range(pages):
                parameters['resultsPerPage'] = '2000'
                parameters['startIndex'] = str(startIndex)
                time.sleep(delay)
                getData = requests.get(link, params=parameters, timeout=10).json()['result']['CVE_Items']
                for eachCVE in getData:
                    rawTemp.append(eachCVE.copy())
                startIndex += 2000
            raw['result']['CVE_Items'] = rawTemp
            return raw
        elif 'cpe':
            for eachPage in range(pages):
                parameters['resultsPerPage'] = '2000'
                parameters['startIndex'] = str(startIndex)
                time.sleep(delay)
                getData = requests.get(link, params=parameters, timeout=10).json()['result']['cpes']
                for eachCPE in getData:
                    rawTemp.append(eachCPE.copy())
                startIndex += 2000
            raw['result']['cpes'] = rawTemp
            return raw

@click.command()							
@click.argument('keyword', type=str)
@click.option('--outfile', type=str, default="sample.txt", help='Output file name')

def main(keyword, outfile):
    result = __get("cve",keyword,20,"10104e42-85d4-4555-936b-bc62d8633fb6",True)
    # print(json.dumps(result, indent=4, sort_keys=True))
    print("Keyword: {}".format(keyword))
    print("Vulnerabilities: [{}] \n".format(result['totalResults']))

    for cve in result['result']['CVE_Items']:
        print("{} \n".format(json.dumps(cve['cve']['CVE_data_meta']['ID'])))
        #some results dont have cvssv3 so implement a check for cvssv2 as well 
        # print("Impact {}".format(json.dumps(cve['impact']['baseMetricV3']['cvssV3']['baseSeverity']))) 
        print("{} \n".format(json.dumps(cve['cve']['description']['description_data'][0]['value']))) 
        # print(cve.keys())
        # print(cve['cve'])

    with open('sample.txt', 'w+') as outfile:
        json.dump(result, outfile, indent=4, sort_keys=True)

if __name__ == '__main__':
    main()