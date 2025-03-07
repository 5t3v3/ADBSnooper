import subprocess
import re
from tqdm import tqdm
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Function to print the banner for the tool
def print_banner():
    banner = """
  ADBSnooper - Sensitive Data Scanner for Android Apps
  ====================================================
  """
    print(Fore.CYAN + banner)

# Function to check ADB connection
def check_adb_connection():
    try:
        # Run adb devices command to check connected devices
        result = subprocess.run(['adb', 'devices'], capture_output=True, text=True)
        if 'device' in result.stdout:
            return True
        else:
            print(Fore.RED + "No device connected.")
            return False
    except Exception as e:
        print(Fore.RED + f"Error checking ADB connection: {e}")
        return False

# Function to restart adb with root permissions
def adb_root():
    try:
        # Restart adb server with root privileges
        subprocess.run(['adb', 'root'], capture_output=True, text=True)
        print(Fore.GREEN + "ADB is now running with root privileges.")
    except Exception as e:
        print(Fore.RED + f"Error restarting ADB with root: {e}")

# Function to remount the file system with write permissions (only needed for some rooted devices)
def adb_remount():
    try:
        subprocess.run(['adb', 'remount'], capture_output=True, text=True)
        print(Fore.GREEN + "File system is now remounted with write permissions.")
    except Exception as e:
        print(Fore.RED + f"Error remounting the file system: {e}")

# Function to navigate to the app's directory
def get_app_data_dir(package_name):
    try:
        # Use adb to list the contents of the app's data directory
        cmd = f'adb shell ls /data/data/{package_name}'
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        if result.returncode == 0:
            print(Fore.GREEN + f"Found data directory for {package_name}: /data/data/{package_name}")
            return f'/data/data/{package_name}'
        else:
            print(Fore.RED + f"Unable to access directory for {package_name}")
            return None
    except Exception as e:
        print(Fore.RED + f"Error accessing directory: {e}")
        return None

# Function to identify file types using the 'file' command
def get_file_type(file_path):
    try:
        cmd = f'adb shell file -b {file_path}'  # Use 'file' to get MIME type
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            return "Unknown"
    except Exception as e:
        print(Fore.RED + f"Error getting file type for {file_path}: {e}")
        return "Unknown"

# Function to check if a file is binary (non-text)
def is_binary(file_path):
    try:
        cmd = f'adb shell file -b {file_path}'
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        return 'text' not in result.stdout.lower()
    except Exception as e:
        print(Fore.RED + f"Error checking file type for {file_path}: {e}")
        return False

# Function to use `strings` to read a file's content and search for sensitive data
def scan_file_for_sensitive_data(file_path, sensitive_patterns):
    sensitive_data_found = []
    try:
        # Use adb shell strings to extract readable text from a binary file
        cmd = f'adb shell strings {file_path}'
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True)

        if result.returncode != 0:
            print(Fore.RED + f"Failed to read file {file_path} using strings.")
            return sensitive_data_found

        file_content = result.stdout
        
        # Search for sensitive data patterns in the extracted text
        for pattern in sensitive_patterns:
            if re.search(pattern, file_content, re.IGNORECASE):
                sensitive_data_found.append((file_path, file_content))
                break

    except Exception as e:
        print(Fore.RED + f"Error scanning file {file_path}: {e}")
    
    return sensitive_data_found

# Function to check the files in the directory for sensitive data
def scan_sensitive_data(directory, sensitive_patterns):
    sensitive_files = []
    db_files = []
    xml_files = []
    json_files = []
    data_files = []
    other_files = []

    try:
        # Use adb to list files inside the directory
        cmd = f'adb shell find {directory} -type f'
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        
        if result.returncode != 0:
            print(Fore.RED + "Failed to list files in directory.")
            return [], [], [], [], []

        files = result.stdout.splitlines()
        
        # Progress bar for the files being scanned
        for file_path in tqdm(files, desc="Scanning Files", unit="file"):
            # Detect the file type
            file_type = get_file_type(file_path.strip())

            # Classify file types
            if file_path.endswith('.db'):
                db_files.append(file_path.strip())
            elif file_path.endswith('.xml'):
                xml_files.append(file_path.strip())
            elif file_path.endswith('.json'):  # Check for .json files
                json_files.append(file_path.strip())
            elif file_type == "data":
                data_files.append(file_path.strip())
            elif file_type == "ASCII text" or file_type == "UTF-8 Unicode text":
                other_files.append(file_path.strip())
            else:
                # Files that don't fit into any category
                other_files.append(file_path.strip())

            # Skip binary files to prevent decoding errors
            if is_binary(file_path.strip()):
                continue

            # Use `strings` to scan the file for sensitive data
            sensitive_data = scan_file_for_sensitive_data(file_path, sensitive_patterns)
            if sensitive_data:
                sensitive_files.extend(sensitive_data)

        return sensitive_files, db_files, xml_files, json_files, data_files, other_files

    except Exception as e:
        print(Fore.RED + f"Error scanning files: {e}")
        return [], [], [], [], []

# Main function to orchestrate the tasks
def main(package_name, custom_keywords):
    # Default sensitive patterns including JWT-like tokens
    sensitive_patterns = [
	    r'password',
	    r'api_key',
	    r'token',
	    r'private',
	    r'client_id',
	    r'client_secret',
	    r'passport',
	    r'SSN',
	    r'username',
	    r'bearer'
	]    
    # Append custom keywords to sensitive patterns
    if custom_keywords:
        custom_patterns = [keyword.strip() for keyword in custom_keywords.split(',')]
        sensitive_patterns.extend(custom_patterns)

    if not check_adb_connection():
        return
    
    # Restart adb with root permissions
    adb_root()

    # Optionally remount the filesystem (required only for some devices)
    adb_remount()

    # Get app data directory
    data_directory = get_app_data_dir(package_name)
    
    if data_directory:
        print(Fore.YELLOW + f"Scanning for sensitive data in {data_directory}...\n")

        # Scan for sensitive data, DB files, JSON files, and all files
        sensitive_data, db_files, xml_files, json_files, data_files, other_files = scan_sensitive_data(data_directory, sensitive_patterns)
        
        # 1. Display sensitive files
        if sensitive_data:
            print(Fore.MAGENTA + "\n### Sensitive Data Found ###")
            for file_path, content in sensitive_data:
                print(Fore.CYAN + f"File: {file_path}")
                print(f"Content: {content[:100]}...")  # Print the first 100 chars of content
                print(Fore.GREEN + "---------------")  # Separation line between findings
        else:
            print(Fore.RED + "No sensitive data found.")
        
        # Separation line
        print(Fore.GREEN + "\n" + "-"*50 + "\n")

        # 2. Display DB files
        if db_files:
            print(Fore.YELLOW + "### DB Files ###")
            for db_file in db_files:
                print(Fore.CYAN + f"DB File: {db_file}")
        else:
            print(Fore.RED + "No DB files found.")
        
        # Separation line
        print(Fore.GREEN + "\n" + "-"*50 + "\n")

	# 3. Display Data files
        if data_files:
            print(Fore.YELLOW + "### Data Files ###")
            for data_file in data_files:
                print(Fore.CYAN + f"Data File: {data_file}")
        else:
            print(Fore.RED + "No Data files found.")
        
        # Separation line
        print(Fore.GREEN + "\n" + "-"*50 + "\n")

                

	# 4. Display XML files
        if xml_files:
            print(Fore.YELLOW + "### XML Files ###")
            for xml_file in xml_files:
                print(Fore.CYAN + f"XML File: {xml_file}")
        else:
            print(Fore.RED + "No XML files found.")
        
        # Separation line
        print(Fore.GREEN + "\n" + "-"*50 + "\n")

        # 5. Display JSON files
        if json_files:
            print(Fore.YELLOW + "### JSON Files ###")
            for json_file in json_files:
                print(Fore.CYAN + f"JSON File: {json_file}")
        else:
            print(Fore.RED + "No JSON files found.")
        
        # Separation line
        print(Fore.GREEN + "\n" + "-"*50 + "\n")

        # 6. Display Other files (text files and others)
        if other_files:
            print(Fore.YELLOW + "### Other Files ###")
            for other_file in other_files:
                file_type = get_file_type(other_file)
                print(Fore.CYAN + f"File: {other_file}, Type: {file_type}")
        else:
            print(Fore.RED + "No other files found.")

    else:
        print(Fore.RED + "Unable to scan the app data directory.")

if __name__ == "__main__":
    print_banner()
    package_name = input(Fore.YELLOW + "Enter the package name of the app: ").strip()
    custom_keywords = input(Fore.YELLOW + "Enter custom sensitive keywords (comma-separated): ").strip()
    main(package_name, custom_keywords)
