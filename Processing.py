#!/usr/bin/env python3
import os
import subprocess
import sys
import logging
import fcntl
import requests
import json
import urllib3

urllib3.disable_warnings()

# Remove LD_LIBRARY_PATH if set
if 'LD_LIBRARY_PATH' in os.environ:
    del os.environ['LD_LIBRARY_PATH']

SPLUNK_HEC_URL = 'http://localhost:8088/services/collector/event'
SPLUNK_HEC_TOKEN = '49716b73-cbe5-4e50-a488-86bafeb3e548'
path_to_volatility = '/opt/tools/volatility/vol.py'
output_folder = '/opt/splunk/memory'

logging.basicConfig(filename='/opt/splunk/var/log/splunk/volatility2dump_errors.log', level=logging.ERROR, format='%(asctime)s:%(levelname)s:%(message)s')

def run_volatility_plugin(dump_file,profile, plugin, output_folder, memory_dump_name, os_type):
    """Runs a Volatility 2 plugin on the memory dump and saves the JSON output to a file."""
    plugin_args = plugin.split()
    plugin_name = plugin_args[0]

    command = [
        'python2.7',  # Ensuring we still call Python 2 for Volatility 2
        path_to_volatility,
        '-f', dump_file,
        '--profile=' + profile,
        *plugin_args,               # Dynamic profile based on user input
        '--output=json'
    ]
    print(command)
    output_file_path = os.path.join(output_folder, f"{plugin_name}.json")
    print(output_file_path)
    try:
        # Execute the command and save output to file
        with open(output_file_path, 'w') as output_file:
            subprocess.run(command, stdout=output_file, check=True)
        
        with open(output_file_path, 'r', encoding='utf-8') as file:
           data = json.load(file)
           columns = data["columns"]
           rows = data["rows"]
           transformed_data = [dict(zip(columns, row), Plugin=plugin_name, Program="Volatility2", Dump=memory_dump_name, Profile=profile, Category=os_type) for row in rows if columns and row] 


        with open(output_file_path, 'w', encoding='utf-8') as file:
            for item in transformed_data:
                file.write(json.dumps(item) + '\n')

        # Upload the JSON file directly to Splunk
        print("Uploading to Splunk")
        upload_to_splunk(output_file_path)

    except subprocess.CalledProcessError as e:
        logging.error(f"Subprocess error when processing plugin {plugin}: {str(e)}")
    except Exception as e:
        logging.error(f"General error processing plugin {plugin}: {str(e)}")

def upload_to_splunk(file_path):
    """Uploads the JSON data to Splunk via the HTTP Event Collector."""
    headers = {
        'Authorization': f'Splunk {SPLUNK_HEC_TOKEN}',
        'Content-Type': 'application/json'
    }
    with open(file_path, 'r') as file:
        data = file.read()

    json_objects = data.splitlines()
    for json_object in json_objects:
    # Prepare the payload for Splunk
        payload = {
            "event": json_object,
            "sourcetype": "_json_no_timestamp",\
            "index": "memory"
        }
        print(payload)
        response = requests.post(SPLUNK_HEC_URL, headers=headers, json=payload, verify=False)

    if response.status_code != 200:
        logging.error(f"Failed to upload data to Splunk: {response.text}")


def process_memory_dump(dump_file, profile, os_type):
    """Process memory dump using a set of Volatility plugins."""
    memory_dump_name = os.path.splitext(os.path.basename(dump_file))[0]
    output_folder = os.path.join(output_folder, memory_dump_name)
    objects_folder = os.path.join(output_folder, 'objects')
    os.makedirs(output_folder, exist_ok=True)
    os.makedirs(objects_folder, exist_ok=True)
    subfolders = ['memdump', 'procdump', 'dlldump', 'kerneldrivers', 'certs', 'files', 'registry', 'yara']
    for subfolder in subfolders:
        os.makedirs(os.path.join(objects_folder, subfolder), exist_ok=True)

    # Create a mapping between categories and plugins
    categories = {
        "processes": ['pslist', 'psscan', 'cmdline', 'dlllist', 'handles', 'getsids', 'cmdscan', 'consoles', 'privs', 'envars', 'verinfo', 'psxview', 'ldrmodules', 'joblinks', 'sessions'],
        "malware": ['svcscan --verbose', 'getservicesids', 'malfind', 'apihooks', 'idt --verbose', 'gdt', 'threads', 'callbacks', 'devicetree', 'timers'],
        "procmemory": ['vadinfo', 'vadwalk', 'iehistory'],
        "kernelobjects": ['modules', 'modscan', 'ssdt', 'driverscan', 'driverirp', 'drivermodule', 'filescan', 'mutantscan --silent', 'symlinkscan', 'thrdscan', 'unloadedmodules', 'atomscan', 'atoms', 'bigpools', 'objtypescan'],
        "networking": ['netscan', 'sockscan', 'sockets', 'connscan', 'connections'],
        "registry": ['hivescan', 'hivelist', 'hashdump', 'lsadump', 'userassist', 'shellbags', 'shimcache', 'amcache', 'cachedump'],
        "filesystem": ['mbrparser -C', 'mftparser --no-check'],
        "miscellaneous": ['imageinfo', 'kdbgscan', 'kpcrscan', 'messagehooks', 'bioskbd', 'auditpol', 'patcher', 'pagecheck', 'timeliner', 'clipboard', 'editbox', 'deskscan', 'eventhooks', 'gahti', 'gditimers']
    }

    # Handling the "windows" os_type by running all plugins across all categories
    if os_type.lower() == "windows":
        for category, plugins in categories.items():
            for plugin in plugins:
                print("Running", plugin)
                try:
                    run_volatility_plugin(dump_file, profile, plugin, output_folder, memory_dump_name, category)
                except Exception as e:
                    logging.error(f"{str(e)}")
                    print(f"Failed to process plugin {plugin}")

    else:
        # Handle comma-delimited plugin names or single plugin
        requested_plugins = os_type.split(',')

        for plugin in requested_plugins:
            plugin = plugin.strip()  # Remove any leading or trailing whitespace
            matched_category = None

            for category, plugin_list in categories.items():
                if plugin in plugin_list or any(plugin.startswith(p) for p in plugin_list):
                    matched_category = category
                    break

            # If a matching category is found, use it; otherwise, use the provided os_type as the category
            category_name = matched_category if matched_category else "custom"
            print("Running", plugin)
            try:
                run_volatility_plugin(dump_file, profile, plugin, output_folder, memory_dump_name, category_name)
            except Exception as e:
                logging.error(f"{str(e)}")
                print(f"Failed to process plugin {plugin}")


def main():
    lock_file_path = '/tmp/dumpprocess.lock'

    with open(lock_file_path, 'w') as lock_file:
        try:
            fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)

            if len(sys.argv) != 4:
                print("Usage: dumpprocess.py <dump> <profile> <os_type>")
                sys.exit(1)

            profile = sys.argv[2]
            dump_file = sys.argv[1]
            os_type = sys.argv[3]
            process_memory_dump(dump_file, profile, os_type)

        except IOError:
            print(f"{str(IOError)}")
            sys.exit(1)
        except Exception as e:
            logging.error(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    main()

