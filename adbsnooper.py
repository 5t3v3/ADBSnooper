import subprocess
import re
from tqdm import tqdm
from colorama import init, Fore, Style
import shlex

# Initialize colorama for colored terminal output
init(autoreset=True)

def quote_path(path):
    """
    Enclose the file/folder path in double quotes, escaping any embedded double quotes.
    This ensures that paths with spaces are correctly interpreted by the shell.
    """
    return '"' + path.replace('"', r'\"') + '"'

def run_as_root(cmd):
    """
    Run a command on the ADB-connected device with root privileges.
    The provided command string is fully quoted so that file paths with spaces are handled properly.
    
    This function wraps the remote command with 'adb shell su -c' and uses shell=True.
    """
    try:
        # Quote the entire command so that adb shell receives one argument for su -c.
        wrapped_cmd = shlex.quote(cmd)
        full_cmd = f"adb shell su -c {wrapped_cmd}"
        result = subprocess.run(full_cmd, shell=True, capture_output=True, text=True)
        return result
    except Exception as e:
        print(Fore.RED + f"Error running command '{cmd}' as root: {e}")
        return None

def print_banner():
    banner = """
  ADBSnooper - Sensitive Data Scanner for Android Apps
  ====================================================
    """
    print(Fore.CYAN + banner)

def check_adb_connection():
    """
    Check if an ADB-connected device is available.
    """
    try:
        result = subprocess.run(['adb', 'devices'], capture_output=True, text=True)
        if 'device' in result.stdout:
            return True
        else:
            print(Fore.RED + "No device connected.")
            return False
    except Exception as e:
        print(Fore.RED + f"Error checking ADB connection: {e}")
        return False

def adb_remount():
    """
    Remount the /system file system with write permission.
    """
    try:
        cmd = "mount -o remount,rw /system"
        result = run_as_root(cmd)
        if result and result.returncode == 0:
            print(Fore.GREEN + "File system is now remounted with write permissions.")
        else:
            print(Fore.RED + "Failed to remount the file system.")
    except Exception as e:
        print(Fore.RED + f"Error remounting the file system: {e}")

def get_app_data_dir(package_name):
    """
    Verify and return the data directory for the given package.
    """
    try:
        cmd = f"ls /data/data/{package_name}"
        result = run_as_root(cmd)
        if result and result.returncode == 0:
            print(Fore.GREEN + f"Found data directory for {package_name}: /data/data/{package_name}")
            return f"/data/data/{package_name}"
        else:
            print(Fore.RED + f"Unable to access directory for {package_name}")
            return None
    except Exception as e:
        print(Fore.RED + f"Error accessing directory: {e}")
        return None

def get_file_type(file_path):
    """
    Determine the file type using the 'file' command on the remote shell.
    If the file command returns an error (like "cannot open"), this function returns "Unknown".
    """
    try:
        cmd = f"file -b {quote_path(file_path)}"
        result = run_as_root(cmd)
        output = result.stdout if result else ""
        if not result or result.returncode != 0 or "cannot open" in output.lower():
            return "Unknown"
        return output.strip()
    except Exception as e:
        print(Fore.RED + f"Error getting file type for {file_path}: {e}")
        return "Unknown"

def is_binary(file_path):
    """
    Check if a file is binary (non-text) by analyzing its output from the 'file' command.
    If the file returns an error (e.g. "cannot open"), the file is treated as binary so that it's skipped.
    """
    try:
        cmd = f"file -b {quote_path(file_path)}"
        result = run_as_root(cmd)
        output = result.stdout if result else ""
        if not result or result.returncode != 0 or "cannot open" in output.lower():
            return True
        return 'text' not in output.lower()
    except Exception as e:
        print(Fore.RED + f"Error checking file type for {file_path}: {e}")
        return True

def get_file_size(file_path):
    """
    Return the size of a file in bytes using the 'stat' command.
    """
    try:
        cmd = f"stat -c %s {quote_path(file_path)}"
        result = run_as_root(cmd)
        if result and result.returncode == 0:
            try:
                size = int(result.stdout.strip())
                return size
            except Exception:
                return None
        else:
            return None
    except Exception as e:
        print(Fore.RED + f"Error getting file size for {file_path}: {e}")
        return None

def file_is_empty(file_path):
    """
    Check if the file size is 0.
    """
    size = get_file_size(file_path)
    return (size is not None and size == 0)

def scan_file_for_sensitive_data(file_path, sensitive_patterns):
    """
    Use the 'strings' command to extract text from a file and then search for sensitive keywords.
    If any sensitive pattern is found, the file is flagged.
    """
    sensitive_data_found = []
    try:
        cmd = f"strings {quote_path(file_path)}"
        result = run_as_root(cmd)
        if not result or result.returncode != 0:
            print(Fore.RED + f"Failed to read file {file_path} using strings.")
            return sensitive_data_found

        file_content = result.stdout
        for pattern in sensitive_patterns:
            if re.search(pattern, file_content, re.IGNORECASE):
                sensitive_data_found.append((file_path, file_content))
                break
    except Exception as e:
        print(Fore.RED + f"Error scanning file {file_path}: {e}")
    return sensitive_data_found

def scan_sensitive_data(directory, sensitive_patterns):
    """
    Recursively scan a directory for files, classify them by type,
    and search for sensitive information in each file.
    """
    sensitive_files = []
    db_files = []
    xml_files = []
    json_files = []
    data_files = []
    other_files = []

    try:
        cmd = f"find {quote_path(directory)} -type f"
        result = run_as_root(cmd)
        if not result or result.returncode != 0:
            print(Fore.RED + "Failed to list files in directory.")
            return [], [], [], [], [], []
        files = result.stdout.splitlines()
        for file_path in tqdm(files, desc="Scanning Files", unit="file"):
            file_path = file_path.strip()
            if file_is_empty(file_path):
                continue

            file_type = get_file_type(file_path)
            # Classify files by extension or file type
            if file_path.endswith('.db'):
                db_files.append(file_path)
            elif file_path.endswith('.xml'):
                xml_files.append(file_path)
            elif file_path.endswith('.json'):
                json_files.append(file_path)
            elif file_type.lower() == "data":
                data_files.append(file_path)
            elif file_type in ("ASCII text", "UTF-8 Unicode text"):
                other_files.append(file_path)
            else:
                other_files.append(file_path)

            # Skip binary files for text scanning
            if is_binary(file_path):
                continue
            sensitive_data = scan_file_for_sensitive_data(file_path, sensitive_patterns)
            if sensitive_data:
                sensitive_files.extend(sensitive_data)
        return sensitive_files, db_files, xml_files, json_files, data_files, other_files
    except Exception as e:
        print(Fore.RED + f"Error scanning files: {e}")
        return [], [], [], [], [], []

def generate_pdf_report(package_name, sensitive_data, db_files, xml_files, json_files, data_files, other_files):
    """
    Generate a PDF report of scan findings using reportlab.
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_CENTER

        pdf_file = f"ADBSnooper_Report_{package_name}.pdf"
        doc = SimpleDocTemplate(pdf_file, pagesize=A4)
        styles = getSampleStyleSheet()
        report_elements = []

        title_style = ParagraphStyle("TitleStyle", parent=styles["Title"],
                                     alignment=TA_CENTER, fontSize=24, spaceAfter=20)
        report_elements.append(Paragraph("ADBSnooper Scan Report", title_style))
        report_elements.append(Paragraph(f"<b>Application Package:</b> {package_name}", styles["Normal"]))
        report_elements.append(Spacer(1, 12))

        report_elements.append(Paragraph("Sensitive Data Found:", styles["Heading2"]))
        if sensitive_data:
            for file_path, content in sensitive_data:
                truncated = content[:100].replace("\n", " ") + "..."
                report_elements.append(Paragraph(f"<b>File:</b> {file_path}", styles["Normal"]))
                report_elements.append(Paragraph(f"<b>Content Snippet:</b> {truncated}", styles["Normal"]))
                report_elements.append(Spacer(1, 6))
        else:
            report_elements.append(Paragraph("No sensitive data found.", styles["Normal"]))
        report_elements.append(Spacer(1, 12))

        report_elements.append(Paragraph("DB Files:", styles["Heading2"]))
        if db_files:
            for file in db_files:
                report_elements.append(Paragraph(file, styles["Normal"]))
        else:
            report_elements.append(Paragraph("No DB files found.", styles["Normal"]))
        report_elements.append(Spacer(1, 12))

        report_elements.append(Paragraph("XML Files:", styles["Heading2"]))
        if xml_files:
            for file in xml_files:
                report_elements.append(Paragraph(file, styles["Normal"]))
        else:
            report_elements.append(Paragraph("No XML files found.", styles["Normal"]))
        report_elements.append(Spacer(1, 12))

        report_elements.append(Paragraph("JSON Files:", styles["Heading2"]))
        if json_files:
            for file in json_files:
                report_elements.append(Paragraph(file, styles["Normal"]))
        else:
            report_elements.append(Paragraph("No JSON files found.", styles["Normal"]))
        report_elements.append(Spacer(1, 12))

        report_elements.append(Paragraph("Data Files:", styles["Heading2"]))
        if data_files:
            for file in data_files:
                report_elements.append(Paragraph(file, styles["Normal"]))
        else:
            report_elements.append(Paragraph("No Data files found.", styles["Normal"]))
        report_elements.append(Spacer(1, 12))

        report_elements.append(Paragraph("Other Files:", styles["Heading2"]))
        if other_files:
            for file in other_files:
                ft = get_file_type(file)
                report_elements.append(Paragraph(f"{file} (Type: {ft})", styles["Normal"]))
        else:
            report_elements.append(Paragraph("No other files found.", styles["Normal"]))
        report_elements.append(Spacer(1, 12))

        doc.build(report_elements)
        print(Fore.GREEN + f"PDF report generated successfully: {pdf_file}")
    except Exception as e:
        print(Fore.RED + f"Failed to generate PDF report: {e}")

def main(package_name, custom_keywords):
    # Predefined sensitive keywords/patterns
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
    if custom_keywords:
        custom_patterns = [keyword.strip() for keyword in custom_keywords.split(',')]
        sensitive_patterns.extend(custom_patterns)

    if not check_adb_connection():
        return

    print(Fore.YELLOW + "Executing commands with root privileges using 'adb shell su -c'...")
    adb_remount()
    data_directory = get_app_data_dir(package_name)
    if not data_directory:
        print(Fore.RED + "Unable to scan the app data directory.")
        return

    print(Fore.YELLOW + f"Scanning for sensitive data in {data_directory}...\n")
    sensitive_data, db_files, xml_files, json_files, data_files, other_files = scan_sensitive_data(
        data_directory, sensitive_patterns
    )

    if sensitive_data:
        print(Fore.MAGENTA + "\n### Sensitive Data Found ###")
        for file_path, content in sensitive_data:
            print(Fore.CYAN + f"File: {file_path}")
            print(f"Content: {content[:100]}...")
            print(Fore.GREEN + "---------------")
    else:
        print(Fore.RED + "No sensitive data found.")

    print(Fore.GREEN + "\n" + "-" * 50 + "\n")
    if db_files:
        print(Fore.YELLOW + "### DB Files ###")
        for db_file in db_files:
            print(Fore.CYAN + f"DB File: {db_file}")
    else:
        print(Fore.RED + "No DB files found.")

    print(Fore.GREEN + "\n" + "-" * 50 + "\n")
    if data_files:
        print(Fore.YELLOW + "### Data Files ###")
        for data_file in data_files:
            print(Fore.CYAN + f"Data File: {data_file}")
    else:
        print(Fore.RED + "No Data files found.")

    print(Fore.GREEN + "\n" + "-" * 50 + "\n")
    if xml_files:
        print(Fore.YELLOW + "### XML Files ###")
        for xml_file in xml_files:
            print(Fore.CYAN + f"XML File: {xml_file}")
    else:
        print(Fore.RED + "No XML files found.")

    print(Fore.GREEN + "\n" + "-" * 50 + "\n")
    if json_files:
        print(Fore.YELLOW + "### JSON Files ###")
        for json_file in json_files:
            print(Fore.CYAN + f"JSON File: {json_file}")
    else:
        print(Fore.RED + "No JSON files found.")

    print(Fore.GREEN + "\n" + "-" * 50 + "\n")
    if other_files:
        print(Fore.YELLOW + "### Other Files ###")
        for other_file in other_files:
            ft = get_file_type(other_file)
            print(Fore.CYAN + f"File: {other_file}, Type: {ft}")
    else:
        print(Fore.RED + "No other files found.")

    generate_pdf = input(Fore.YELLOW + "\nWould you like to generate a PDF report? (y/n): ").strip().lower()
    if generate_pdf == 'y':
        generate_pdf_report(package_name, sensitive_data, db_files, xml_files, json_files, data_files, other_files)

if __name__ == "__main__":
    print_banner()
    package_name = input(Fore.YELLOW + "Enter the package name of the app: ").strip()
    custom_keywords = input(Fore.YELLOW + "Enter custom sensitive keywords (comma-separated): ").strip()
    main(package_name, custom_keywords)
