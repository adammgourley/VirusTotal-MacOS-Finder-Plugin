# Takes a file path as input, calls 'scan.py' to conduct a VirusTotal hash lookup, or VirusTotal file scan, which returns
# the report in the variable virustotal_file_report. From there, this script handles the output of the report. Writing to a
# file the report contents and opening it in a web browser.

# This script is meant to be called from a Quick Actions automation in MacOS, allowing you to right-click a file and easily
# have it scanned with VirusTotal, and the results are opened in the browser once ready. The results are parsed in order
# to provide the useful information in a clear way, rather than having to read through the JSON contents.

# Example usage by calling script directly:
#  >  python3 main.py "/path/to/file/to/scan.exe"

# TODO
# - Figure out how to initiate from Quick Actions
# - Upload to GitHub

import subprocess
import json
import sys
import os
import configparser
from datetime import datetime
import webbrowser

def main():
    # If no file path is provided, print instructions on how to use.
    if len(sys.argv) < 2:
        print("\nMust provide a file to scan (full path).\n")
        print("Example usage:\n> python3 main.py /path/to/file.txt\n")
        return
    
    # Ensures the directories exist for report and log output. Should already be there because of the installation script.
    virustotal_dir = f"{os.getenv('HOME')}/.virustotal_plugin"
    if not os.path.exists(virustotal_dir):
        # Create the directory if it does not exist
        try:
            os.makedirs(virustotal_dir)
            os.makedirs(f"{virustotal_dir}/reports")
            os.makedirs(f"{virustotal_dir}/logs")
        except:
            print("ERROR: Unable to create required output directories. Exiting.")
    
    # Generate output file paths (report, stdout log, stderr log)
    time_of_report = datetime.now().strftime("%Y-%m-%d_%H:%M:%S")
    html_report_output_path = f"{os.getenv('HOME')}/.virustotal_plugin/reports/{os.path.basename(sys.argv[1])}_{time_of_report}_report.html"
    stdout_report_output_path = f"{os.getenv('HOME')}/.virustotal_plugin/logs/{os.path.basename(sys.argv[1])}_{time_of_report}_stdout.log"
    stderr_report_output_path = f"{os.getenv('HOME')}/.virustotal_plugin/logs/{os.path.basename(sys.argv[1])}_{time_of_report}_stderr.log"
    
    # Parses a dict object of the VirusTotal report and writes it to a file in HTML format
    def WriteHTMLReport(report, file_path):
        # Extracting data
        data_id = report['data']['id']
        data_type = report['data']['type']
        self_link = report['data']['links']['self']
        item_link = report['data']['links']['item']
        status = report['data']['attributes']['status']
        results = report['data']['attributes']['results']
        stats = report['data']['attributes']['stats']
        date = report['data']['attributes']['date']
        file_info = report['meta']['file_info']

        # Building the HTML report
        html = f"""
        <html>
        <head>
            <title>VirusTotal Analysis Report</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    margin: 0;
                    padding: 0;
                    background-color: #f4f4f4;
                }}
                .container {{
                    width: 80%;
                    margin: auto;
                    overflow: hidden;
                }}
                .header {{
                    background: #50b3a2;
                    color: #fff;
                    padding: 20px 0;
                    text-align: center;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin: 20px 0;
                }}
                table, th, td {{
                    border: 1px solid #ddd;
                }}
                th, td {{
                    padding: 10px;
                    text-align: left;
                }}
                th {{
                    background-color: #f2f2f2;
                }}
                .footer {{
                    background: #50b3a2;
                    color: #fff;
                    text-align: center;
                    padding: 10px 0;
                    margin-top: 20px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>VirusTotal Analysis Report</h1>
                </div>
                <h2>Data</h2>
                <p><strong>File Path:</strong> {sys.argv[1]}</p>
                <p><strong>ID:</strong> {data_id}</p>
                <p><strong>Type:</strong> {data_type}</p>
                <p><strong>Self Link:</strong> <a href="{self_link}">{self_link}</a></p>
                <p><strong>Item Link:</strong> <a href="{item_link}">{item_link}</a></p>
                <h2>Attributes</h2>
                <p><strong>Status:</strong> {status}</p>
                <h3>Stats</h3>
                <table>
                    <tr>
                        <th>Malicious</th>
                        <th>Suspicious</th>
                        <th>Undetected</th>
                        <th>Harmless</th>
                        <th>Timeout</th>
                        <th>Confirmed Timeout</th>
                        <th>Failure</th>
                        <th>Type Unsupported</th>
                    </tr>
                    <tr>
                        <td>{stats['malicious']}</td>
                        <td>{stats['suspicious']}</td>
                        <td>{stats['undetected']}</td>
                        <td>{stats['harmless']}</td>
                        <td>{stats['timeout']}</td>
                        <td>{stats['confirmed-timeout']}</td>
                        <td>{stats['failure']}</td>
                        <td>{stats['type-unsupported']}</td>
                    </tr>
                </table>
                <h3>Results</h3>
                <table>
                    <tr>
                        <th>Engine</th>
                        <th>Method</th>
                        <th>Version</th>
                        <th>Update</th>
                        <th>Category</th>
                        <th>Result</th>
                    </tr>"""
        
        for engine, result in results.items():
            html += f"""
                    <tr>
                        <td>{result['engine_name']}</td>
                        <td>{result['method']}</td>
                        <td>{result['engine_version']}</td>
                        <td>{result['engine_update']}</td>
                        <td>{result['category']}</td>
                        <td>{result['result']}</td>
                    </tr>"""
        
        html += f"""
                </table>
                <h3>Meta</h3>
                <p><strong>SHA256:</strong> {file_info['sha256']}</p>
                <p><strong>MD5:</strong> {file_info['md5']}</p>
                <p><strong>SHA1:</strong> {file_info['sha1']}</p>
                <p><strong>Size:</strong> {file_info['size']} bytes</p>
                <p><strong>Date:</strong> {date}</p>
                <div class="footer">
                    <p>VirusTotal Analysis for {sys.argv[1]}</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Write the output to specified file path
        with open(file_path, 'w') as f:
            f.write(html)
    
    # Initiate scan.py with 
    virustotal_file_report = subprocess.run(['/opt/homebrew/bin/python3', f"{virustotal_dir}/src/scan.py", f"{sys.argv[1]}"], capture_output=True, text=True)

    # Try to generate report by converting stdout to dict, parsing the dict and building html code, and writing that to
    # a specified html file path
    try:
        # Try to convert stdout to json
        virustotal_file_report_dict = json.loads(virustotal_file_report.stdout)
        # Write report to HTML file in current directory
        WriteHTMLReport(report=virustotal_file_report_dict, file_path=f"{html_report_output_path}")
    except:
        print(f"\nERROR: Unable to generate report from the following output. You can view more in the logs.\n\n{virustotal_file_report.stdout}\n")

    # Write stdout and stderr to log
    with open(f"{stdout_report_output_path}", 'w') as f:
        f.write(virustotal_file_report.stdout)
    with open(f"{stderr_report_output_path}", "w") as f:
        if virustotal_file_report.stderr != "":
            f.write(virustotal_file_report.stderr)

    # Open report in browser
    if os.path.exists(html_report_output_path):
        try:
            subprocess.run(["open", html_report_output_path])
        except:
            print("ERROR: Failed to open report in browser.")
    else:
        print("ERROR: Unable to open report. It may not exist.")

if __name__ == "__main__":
    main()