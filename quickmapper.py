import json
import os
from collections import defaultdict

def load_json(file_path):
    """Load a BloodHound JSON file."""
    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)

def extract_high_value_targets(bloodhound_json):
    """Extracts high-value accounts based on BloodHound data."""
    high_value_accounts = defaultdict(list)
    
    nodes = bloodhound_json.get("nodes", [])
    
    for node in nodes:
        properties = node.get("properties", {})
        name = properties.get("name", "Unknown")

        # Identify high-value users
        if properties.get("highvalue", False):
            high_value_accounts["High Value"].append(name)

        # Check for Domain Admins & Enterprise Admins
        if "admincount" in properties and properties["admincount"] == 1:
            high_value_accounts["Domain Admins / Enterprise Admins"].append(name)

        # Users with Kerberoastable SPNs
        if properties.get("hasspn", False):
            high_value_accounts["Kerberoastable Accounts"].append(name)

        # Unconstrained Delegation Accounts
        if properties.get("unconstraineddelegation", False):
            high_value_accounts["Unconstrained Delegation"].append(name)

        # Users with Delegation Rights
        if properties.get("allowedtodelegate", False):
            high_value_accounts["Allowed to Delegate"].append(name)

    return high_value_accounts

def extract_sessions(bloodhound_json, high_priv_accounts):
    """Extracts session data and finds where privileged users are logged in."""
    session_data = defaultdict(set)
    
    nodes = bloodhound_json.get("nodes", [])
    
    for node in nodes:
        properties = node.get("properties", {})
        host = properties.get("name", "Unknown")
        sessions = node.get("sessions", [])

        for session in sessions:
            username = session.get("user", {}).get("name", "")
            if username in high_priv_accounts:
                session_data[host].add(username)

    return session_data

def extract_unconstrained_delegation_principals(bloodhound_json):
    """Extracts principals (computers/accounts) trusted for Unconstrained Delegation."""
    delegation_targets = []
    
    nodes = bloodhound_json.get("nodes", [])
    
    for node in nodes:
        properties = node.get("properties", {})
        name = properties.get("name", "Unknown")

        if properties.get("unconstraineddelegation", False):
            delegation_targets.append(name)

    return delegation_targets

def print_results(targets, sessions, unconstrained_delegation_targets):
    """Prints extracted high-value accounts, sessions, and delegation principals."""
    print("\n\033[1;32mTop Accounts to Target (BloodHound Analysis)\033[0m\n")
    
    for category, accounts in targets.items():
        print(f"\033[1;34m{category}\033[0m ({len(accounts)} found):")
        for account in accounts:
            print(f"  - {account}")
        print("\n")

    print("\n\033[1;32mPrivileged User Sessions (Lateral Movement Targets)\033[0m\n")
    for host, users in sessions.items():
        print(f"\033[1;34m{host}\033[0m ({len(users)} privileged users logged in):")
        for user in users:
            print(f"  - {user}")
        print("\n")

    print("\n\033[1;32mPrincipals Trusted for Unconstrained Delegation\033[0m\n")
    if unconstrained_delegation_targets:
        for target in unconstrained_delegation_targets:
            print(f"  - {target}")
    else:
        print("  No Unconstrained Delegation principals found.\n")

def main():
    folder = input("Enter the path to your BloodHound JSON files: ")

    if not os.path.isdir(folder):
        print("Invalid directory. Please enter a valid path.")
        return

    high_value_targets = defaultdict(list)
    all_sessions = defaultdict(set)
    unconstrained_delegation_targets = []

    for filename in os.listdir(folder):
        if filename.endswith(".json"):
            file_path = os.path.join(folder, filename)
            print(f"Processing {file_path}...")
            try:
                bloodhound_data = load_json(file_path)
                
                # Extract high-value accounts
                extracted_targets = extract_high_value_targets(bloodhound_data)
                for key, value in extracted_targets.items():
                    high_value_targets[key].extend(value)

                # Extract session data
                high_priv_accounts = set(high_value_targets["Domain Admins / Enterprise Admins"] +
                                         high_value_targets["High Value"])
                extracted_sessions = extract_sessions(bloodhound_data, high_priv_accounts)
                for key, value in extracted_sessions.items():
                    all_sessions[key].update(value)

                # Extract Unconstrained Delegation Principals
                delegation_targets = extract_unconstrained_delegation_principals(bloodhound_data)
                unconstrained_delegation_targets.extend(delegation_targets)

            except Exception as e:
                print(f"Error processing {filename}: {e}")

    print_results(high_value_targets, all_sessions, unconstrained_delegation_targets)

if __name__ == "__main__":
    main()
