import pandas as pd
import re

# List of common attack tools to look for
attack_tools = [
    'nmap', 'mimikatz', 'metasploit', 'msfconsole', 'wce.exe', 'fgdump.exe',
    'psExec.exe', 'schtasks.exe', 'at.exe', 'netcat', 'nc.exe', 'hydra', 'john.exe',
    'ophcrack', 'sqlmap', 'nessus', 'burpsuite', 'cain.exe', 'wireshark', 'tcpdump',
    'hashcat', 'aircrack-ng', 'kismet', 'snort', 'gobuster', 'dirbuster', 'nikto',
    'sqlninja', 'medusa', 'putty', 'winscp', 'net.exe', 'route.exe', 'scp', 'w3af', 'zaproxy'
]


def search_for_malicious_processes(file_path, attack_tools):
    data = pd.read_csv(file_path)

    # Extract just the file names (without the path or extension)
    data['Process Name'] = data['Source process path'].str.extract(r'\\([^\\]+)\.exe')[0]

    # Normalize the process names to lowercase
    data['Process Name'] = data['Process Name'].str.lower()

    # Prepare regex pattern for exact matches with word boundaries
    pattern = r'\b(' + '|'.join(attack_tools) + r')\b'

    # Use regex search to match process names exactly
    is_malicious_process = data['Process Name'].str.contains(pattern, flags=re.IGNORECASE, na=False)
    malicious_process_data = data[is_malicious_process]

    # Output the filtered data to a new CSV file
    output_path = file_path.replace('.csv', '_malicious_process_details.csv')
    malicious_process_data.to_csv(output_path, index=False)
    print(f"Details of malicious process activities have been saved to {output_path}")


def main():
    file_path = r"filepath.csv"
    search_for_malicious_processes(file_path, attack_tools)


if __name__ == "__main__":
    main()
