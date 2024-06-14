# Takes a file path as input, checks if it matches any SHA-256 hash values on VirusTotal and returns a report if it does. If not,
# the file is uploaded to VirusTotal, and the script will wait until the report is ready to return it.

import sys
import requests
import time
import datetime
import hashlib
import configparser
import json
import os

# Execute script
def main(file_path, api_key):
    # Gets hash of file
    def ComputeHash(file_path, algorithm="sha256"):
        hash_function = hashlib.new(algorithm)
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_function.update(chunk)
        return hash_function.hexdigest()

    # Checks the results of a VirusTotal file scan by ID
    def GetVTReportFromID(api_key, vt_file_id):
        url = f"https://www.virustotal.com/api/v3/analyses/{vt_file_id}"

        headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }

        response = requests.get(url, headers=headers)

        return response.text

    # Get report from VirusTotal by hash
    def GetVirusTotalReportFromHash(api_key, hash_value):
        url = f"https://www.virustotal.com/api/v3/files/{hash}"

        headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }

        response = requests.get(url, headers=headers)

        return response.text

    # Checks if a file is over 32mb. If it is, return true otherwise false
    def CheckIfOver32MB(file_path):
        # Get the size of the file in bytes
        file_size = os.path.getsize(file_path)
        
        # Define 32 MB in bytes
        size_limit = 32 * 1024 * 1024
        
        # Check if the file size is greater than 32 MB
        return file_size > size_limit

    # Uploads file under 32mb to VirusTotal for analysis. Returns VirusTotal ID
    def UploadFileForAnalysis_under32mb(api_key, file_path, password=False):
        # URL for VirusTotal file analyzer API
        url = "https://www.virustotal.com/api/v3/files"

        # Get file binary to upload
        files = { "file": (file_path, open(file_path, "rb"), "application/octet-stream") }
        
        headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }

        # If a password provided, submit with that
        if password:
            payload = { "password": password }
            response = requests.post(url, files=files, headers=headers, data=payload)
            return response.text

        # If no password provided, submit without it
        response = requests.post(url, files=files, headers=headers)

        response_dict = json.loads(response.text)

        return response_dict["data"]["id"]

    # Returns report for a file larger than 32mb by uploading
    def UploadFileForAnalysis_over32mb(api_key, file_path):
        # Gets the URL to use and returns it
        def GetURLForLargeFiles(api_key):
            url = "https://www.virustotal.com/api/v3/files/upload_url"

            headers = {
                "accept": "application/json",
                "x-apikey": api_key
            }

            response = requests.get(url, headers=headers)

            upload_url = json.loads(response.text)
            
            return upload_url["data"]

        # Use function GetURLForLargeFiles to get specific URL to use for upload
        url = GetURLForLargeFiles(api_key=api_key)

        # Get file binary to upload
        files = { "file": (file_path, open(file_path, "rb"), "application/octet-stream") }
        
        headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }

        # Submit file
        response = requests.post(url, files=files, headers=headers)
        return response.text

    # Tries to find a report based off the hash of the file. If none is found, this is passed
    # and the function won't return yet. It will move on to upload the file and scan it
    try:
        # Get hash of file
        file_hash = ComputeHash(file_path, algorithm="sha256")

        # Look for a VT report by file hash
        hash_report = GetVirusTotalReportFromHash(api_key=api_key, hash_value=file_hash)

        # Create a dict object to parse of the returned report
        hash_report_dict = json.loads(hash_report)

        # If no errors are in the hash report dict object, a report was found. Return it
        if "error" not in hash_report_dict:
            return hash_report
    except Exception as e:
        return e

    # Check for file size. If the file is over 32mb, it will use a different method to get the 
    # report. Otherwise, it will use a simpiler method to upload and get the report.
    try:
        if CheckIfOver32MB(file_path=file_path):
            # Check if file is over the VirusTotal 650mb limit. If so, return error 'file too big'
            if os.path.getsize(file_path) > 650 * 1024 * 1024:
                return "File too big for VirusTotal scan (650MB max allowed)"
            
            # Upload file to VirusTotal using alternate function that generates a specific URL for
            # large files to be uplaoded to. Returns the VT ID
            initial_large_file_scan_report = UploadFileForAnalysis_over32mb(api_key=api_key, file_path=file_path)
            initial_large_file_scan_report_dict = json.loads(initial_large_file_scan_report)
            virustotal_file_id = initial_large_file_scan_report_dict["data"]["id"]

            # Wait for scan to complete. Since the file is larger, waits 30 seconds initially.
            time.sleep(30)

            # Gets the report from VT ID returned prior
            file_scan_report = GetVTReportFromID(api_key=api_key, vt_file_id=virustotal_file_id)

            # Checks if the report returned includes "queued". If so, waits a bit and tries again. Repeats for 4 minutes until giving up
            # and just returning the URL on where to find the report instead.
            file_scan_report_dict = json.loads(file_scan_report)
            if file_scan_report_dict["data"]["attributes"]["status"] == "queued":
                # Loop and keep fetching report until it is no longer queued. Breaks after 12 attempts and returns with URL instead of report
                ticker = 0
                while ticker < 12:
                    # Wait 20 seconds before trying to get report again.
                    time.sleep(20)
                    ticker += 1

                    # Fetch report again
                    file_scan_report = GetVTReportFromID(api_key=api_key, vt_file_id=virustotal_file_id)
                    file_scan_report_dict = json.loads(file_scan_report)

                    if file_scan_report_dict["data"]["attributes"]["status"] == "queued":
                        continue
                    elif file_scan_report_dict["data"]["attributes"]["status"] == "completed":
                        # Return report now that it has completed
                        return file_scan_report
                    
                # If it makes it all the way through the 120 second loop, just return the report URL rather than continuing forever.
                return f"Report unavailable after waiting 240 seconds."

            # If report is ready after first 10 seconds, return it
            return file_scan_report

        elif not CheckIfOver32MB(file_path=file_path):
            # File under 32mb. Uploads to VirusTotal and returns VirusTotal ID
            virustotal_file_id = UploadFileForAnalysis_under32mb(file_path=file_path, api_key=api_key)
            
            # Wait for 10 seconds and let VirusTotal run the scans before trying to get the report.
            time.sleep(10)

            # Fetch the report
            file_scan_report = GetVTReportFromID(api_key=api_key, vt_file_id=virustotal_file_id)
            
            # Checks if the report returned includes "queued". If so, waits a bit and tries again. Repeats for 4 minutes until giving up
            # and just returning the URL on where to find the report instead.
            file_scan_report_dict = json.loads(file_scan_report)
            if file_scan_report_dict["data"]["attributes"]["status"] == "queued":
                # Loop and keep fetching report until it is no longer queued. Breaks after 12 attempts and returns with URL instead of report
                ticker = 0
                while ticker < 12:
                    # Wait 20 seconds before trying to get report again.
                    time.sleep(20)
                    ticker += 1

                    # Fetch report again
                    file_scan_report = GetVTReportFromID(api_key=api_key, vt_file_id=virustotal_file_id)
                    file_scan_report_dict = json.loads(file_scan_report)

                    if file_scan_report_dict["data"]["attributes"]["status"] == "queued":
                        continue
                    elif file_scan_report_dict["data"]["attributes"]["status"] == "completed":
                        # Return report now that it has completed
                        return file_scan_report
                    
                # If it makes it all the way through the 120 second loop, just return the report URL rather than continuing forever.
                return f"Report unavailable after waiting 240 seconds."

            # If report is ready after first 10 seconds, return it
            return file_scan_report
        else:
            return FileNotFoundError
    except Exception as e:
        return e

# Gets API key from config.ini file from the "[API] api_key" value
def GetAPIKey(file_path):
    # Create a ConfigParser object
    config = configparser.ConfigParser()
    
    # Read the config file
    config.read(file_path)
    
    # Retrieve the key value from the [API] section
    api_key = config.get('API', 'api_key')
    
    return api_key

# Execute main() with first argument passed
if __name__ == '__main__':
    results = main(file_path=sys.argv[1], api_key=GetAPIKey(f"{os.getenv('HOME')}/.virustotal_plugin/config.ini"))
    print(results)