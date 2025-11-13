#fetch hash
# from app.backend.report_generator import file_hash  

#get curl command
import mitreDatabaseOperations
import json
import requests
import os
from dotenv import load_dotenv
load_dotenv()

filehash = "0efc314b1b7f6c74e772eb1f8f207ed50c2e702aed5e565081cbcf8f28f0fe26"
url = f"https://www.virustotal.com/api/v3/files/{filehash}/behaviour_mitre_trees"

def print_mitre(parsed: dict):
    print(f"File Hash: {parsed['file_hash']}\n")

    for sandbox, tactics in parsed.items():
        if sandbox == "file_hash":
            continue
        print(f"Sandbox: {sandbox}")
        for tactic in tactics:
            print(f"  Tactic: {tactic['tactic_name']} ({tactic['tactic_id']})")
            for technique in tactic["techniques"]:
                print(f"    Technique: {technique['technique_name']} ({technique['technique_id']})")
        print()


def mitre_report(filehash: str, response):
    parsed = {
        "file_hash": filehash, 
        
        }
    
    for sandbox_name, sandbox_data in response["data"].items():
        parsed[sandbox_name] = []  # each sandbox holds a list of tactic-technique mappings
        
        for tactic in sandbox_data.get("tactics", []):
            tactic_entry = {
            "tactic_id": tactic.get("id"),
            "tactic_name": tactic.get("name"),
            "techniques": []
        }

            for technique in tactic.get("techniques", []):
                tactic_entry["techniques"].append({
                "technique_id": technique.get("id"),
                "technique_name": technique.get("name")
            })

            parsed[sandbox_name].append(tactic_entry)

    #print(json.dumps(parsed, indent=2))
    print_mitre(parsed)
    pass


headers = {
    "accept": "application/json",
    "x-apikey": os.getenv("VT_API_KEY")
    
}

response = requests.get(url, headers=headers)

#print(response.status_code)
#print(response.json())

mitre_report(filehash, response.json())

#exists = requests.get(f"https://www.virustotal.com/api/v3/files/{hash}", headers=headers)



#print(exists.status_code)
#print(exists.json())



"""
dummy_response = {
    {
  "data": {
    "CAPE Sandbox": {
      "tactics": [
        {
          "id": "TA0011",
          "name": "Command and Control",
          "link": "https://attack.mitre.org/tactics/TA0011/",
          "description": "The adversary is trying to communicate with compromised systems to control them.\n\nCommand and Control consists of techniques that adversaries may use to communicate with systems under their control within a victim network. Adversaries commonly attempt to mimic normal, expected traffic to avoid detection. There are many ways an adversary can establish command and control with various levels of stealth depending on the victim’s network structure and defenses.",
          "techniques": [
            {
              "id": "T1071",
              "name": "Application Layer Protocol",
              "link": "https://attack.mitre.org/techniques/T1071/",
              "description": "Adversaries may communicate using OSI application layer protocols to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server. \nAdversaries may utilize many different protocols, including those used for web browsing, transferring files, electronic mail, DNS, or publishing/subscribing. For connections that occur internally within an enclave (such as those between a proxy or pivot node and other nodes), commonly used protocols are SMB, SSH, or RDP. ",
              "signatures": [
                {
                  "severity": "UNKNOWN",
                  "description": "Adversaries may communicate using application layer protocols to avoid detection/network filtering by blending in with existing traffic."
                }
              ]
            }
          ]
        }
      ]
    },
    "OS X Sandbox": {
      "tactics": [
        {
          "id": "TA0007",
          "name": "Discovery",
          "link": "https://attack.mitre.org/tactics/TA0007/",
          "description": "The adversary is trying to figure out your environment.\n\nDiscovery consists of techniques an adversary may use to gain knowledge about the system and internal network. These techniques help adversaries observe the environment and orient themselves before deciding how to act. They also allow adversaries to explore what they can control and what’s around their entry point in order to discover how it could benefit their current objective. Native operating system tools are often used toward this post-compromise information-gathering objective. ",
          "techniques": [
            {
              "id": "T1046",
              "name": "Network Service Discovery",
              "link": "https://attack.mitre.org/techniques/T1046/",
              "description": "Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices, including those that may be vulnerable to remote software exploitation. Common methods to acquire this information include port, vulnerability, and/or wordlist scans using tools that are brought onto a system.   \nWithin cloud environments, adversaries may attempt to discover services running on other cloud hosts. Additionally, if the cloud environment is connected to a on-premises environment, adversaries may be able to identify services running on non-cloud systems as well.\nWithin macOS environments, adversaries may use the native Bonjour application to discover services running on other macOS hosts within a network. The Bonjour mDNSResponder daemon automatically registers and advertises a host’s registered services on the network. For example, adversaries can use a mDNS query (such as dns-sd -B _ssh._tcp .) to find other systems broadcasting the ssh service.",
              "signatures": [
                {
                  "severity": "LOW",
                  "description": "Sample scans a subnet",
                  "match_data": [
                    "17.57.146.7, 17.57.146.9, 17.57.146.11, 17.57.146.10, 17.57.146.12, 17.57.146.150, 17.57.146.151"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "TA0011",
          "name": "Command and Control",
          "link": "https://attack.mitre.org/tactics/TA0011/",
          "description": "The adversary is trying to communicate with compromised systems to control them.\n\nCommand and Control consists of techniques that adversaries may use to communicate with systems under their control within a victim network. Adversaries commonly attempt to mimic normal, expected traffic to avoid detection. There are many ways an adversary can establish command and control with various levels of stealth depending on the victim’s network structure and defenses.",
          "techniques": [
            {
              "id": "T1573",
              "name": "Encrypted Channel",
              "link": "https://attack.mitre.org/techniques/T1573/",
              "description": "Adversaries may employ an encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol. Despite the use of a secure algorithm, these implementations may be vulnerable to reverse engineering if secret keys are encoded and/or generated within malware samples/configuration files.",
              "signatures": [
                {
                  "severity": "INFO",
                  "description": "Uses HTTPS",
                  "match_data": [
                    "HTTP traffic on port 56717 -> 443",
                    "HTTP traffic on port 56746 -> 443",
                    "HTTP traffic on port 56790 -> 443",
                    "HTTP traffic on port 443 -> 56717",
                    "HTTP traffic on port 56769 -> 443",
                    "HTTP traffic on port 443 -> 56679",
                    "HTTP traffic on port 443 -> 56712",
                    "HTTP traffic on port 443 -> 56796",
                    "HTTP traffic on port 443 -> 56797",
                    "HTTP traffic on port 56586 -> 443",
                    "HTTP traffic on port 56781 -> 443",
                    "HTTP traffic on port 56695 -> 443",
                    "HTTP traffic on port 56778 -> 443",
                    "HTTP traffic on port 56789 -> 443",
                    "HTTP traffic on port 443 -> 56607",
                    "HTTP traffic on port 443 -> 56609",
                    "HTTP traffic on port 56793 -> 443",
                    "HTTP traffic on port 56737 -> 443",
                    "HTTP traffic on port 443 -> 56686",
                    "HTTP traffic on port 443 -> 56687",
                    "HTTP traffic on port 443 -> 56722",
                    "HTTP traffic on port 56712 -> 443",
                    "HTTP traffic on port 443 -> 56695",
                    "HTTP traffic on port 56775 -> 443",
                    "HTTP traffic on port 56761 -> 443",
                    "HTTP traffic on port 56687 -> 443",
                    "HTTP traffic on port 56792 -> 443",
                    "HTTP traffic on port 443 -> 56734",
                    "HTTP traffic on port 56773 -> 443",
                    "HTTP traffic on port 443 -> 56737",
                    "HTTP traffic on port 56734 -> 443",
                    "HTTP traffic on port 443 -> 56610",
                    "HTTP traffic on port 443 -> 56611",
                    "HTTP traffic on port 443 -> 56583",
                    "HTTP traffic on port 56648 -> 443",
                    "HTTP traffic on port 443 -> 56585",
                    "HTTP traffic on port 443 -> 56586",
                    "HTTP traffic on port 56795 -> 443",
                    "HTTP traffic on port 56640 -> 443",
                    "HTTP traffic on port 56787 -> 443",
                    "HTTP traffic on port 56609 -> 443",
                    "HTTP traffic on port 56583 -> 443",
                    "HTTP traffic on port 443 -> 56746",
                    "HTTP traffic on port 443 -> 56747",
                    "HTTP traffic on port 56756 -> 443",
                    "HTTP traffic on port 56708 -> 443",
                    "HTTP traffic on port 56784 -> 443",
                    "HTTP traffic on port 56610 -> 443",
                    "HTTP traffic on port 56742 -> 443",
                    "HTTP traffic on port 56771 -> 443",
                    "HTTP traffic on port 443 -> 56639",
                    "HTTP traffic on port 56788 -> 443",
                    "HTTP traffic on port 56794 -> 443",
                    "HTTP traffic on port 443 -> 56756",
                    "HTTP traffic on port 443 -> 56757",
                    "HTTP traffic on port 56679 -> 443",
                    "HTTP traffic on port 443 -> 56640",
                    "HTTP traffic on port 443 -> 56761",
                    "HTTP traffic on port 56785 -> 443",
                    "HTTP traffic on port 56797 -> 443",
                    "HTTP traffic on port 56722 -> 443",
                    "HTTP traffic on port 56607 -> 443",
                    "HTTP traffic on port 56747 -> 443",
                    "HTTP traffic on port 56768 -> 443",
                    "HTTP traffic on port 443 -> 56768",
                    "HTTP traffic on port 443 -> 56769",
                    "HTTP traffic on port 443 -> 56648",
                    "HTTP traffic on port 56585 -> 443",
                    "HTTP traffic on port 56779 -> 443",
                    "HTTP traffic on port 443 -> 56771",
                    "HTTP traffic on port 443 -> 56773",
                    "HTTP traffic on port 56782 -> 443",
                    "HTTP traffic on port 56639 -> 443",
                    "HTTP traffic on port 56796 -> 443",
                    "HTTP traffic on port 443 -> 56778",
                    "HTTP traffic on port 56786 -> 443",
                    "HTTP traffic on port 443 -> 56779",
                    "HTTP traffic on port 443 -> 56774",
                    "HTTP traffic on port 443 -> 56775",
                    "HTTP traffic on port 443 -> 56781",
                    "HTTP traffic on port 443 -> 56782",
                    "HTTP traffic on port 443 -> 56784",
                    "HTTP traffic on port 56757 -> 443",
                    "HTTP traffic on port 443 -> 56780",
                    "HTTP traffic on port 56611 -> 443",
                    "HTTP traffic on port 56686 -> 443",
                    "HTTP traffic on port 56791 -> 443",
                    "HTTP traffic on port 443 -> 56708",
                    "HTTP traffic on port 443 -> 56789",
                    "HTTP traffic on port 56774 -> 443",
                    "HTTP traffic on port 443 -> 56785",
                    "HTTP traffic on port 443 -> 56786",
                    "HTTP traffic on port 443 -> 56787",
                    "HTTP traffic on port 443 -> 56788",
                    "HTTP traffic on port 56780 -> 443",
                    "HTTP traffic on port 443 -> 56792",
                    "HTTP traffic on port 443 -> 56793",
                    "HTTP traffic on port 443 -> 56794",
                    "HTTP traffic on port 443 -> 56795",
                    "HTTP traffic on port 443 -> 56790",
                    "HTTP traffic on port 443 -> 56791"
                  ]
                }
              ]
            },
            {
              "id": "T1571",
              "name": "Non-Standard Port",
              "link": "https://attack.mitre.org/techniques/T1571/",
              "description": "Adversaries may communicate using a protocol and port pairing that are typically not associated. For example, HTTPS over port 8088 or port 587 as opposed to the traditional port 443. Adversaries may make changes to the standard port used by a protocol to bypass filtering or muddle analysis/parsing of network data.\nAdversaries may also make changes to victim systems to abuse non-standard ports. For example, Registry keys and other configuration settings can be used to modify protocol and port pairings.",
              "signatures": [
                {
                  "severity": "INFO",
                  "description": "Detected TCP or UDP traffic on non-standard ports",
                  "match_data": [
                    "192.168.2.10:56581 -> 8.8.8.8:853"
                  ]
                }
              ]
            },
            {
              "id": "T1095",
              "name": "Non-Application Layer Protocol",
              "link": "https://attack.mitre.org/techniques/T1095/",
              "description": "Adversaries may use an OSI non-application layer protocol for communication between host and C2 server or among infected hosts within a network. The list of possible protocols is extensive. Specific examples include use of network layer protocols, such as the Internet Control Message Protocol (ICMP), transport layer protocols, such as the User Datagram Protocol (UDP), session layer protocols, such as Socket Secure (SOCKS), as well as redirected/tunneled protocols, such as Serial over LAN (SOL).\nICMP communication between hosts is one example. Because ICMP is part of the Internet Protocol Suite, it is required to be implemented by all IP-compatible hosts. However, it is not as commonly monitored as other Internet Protocols such as TCP or UDP and may be used by adversaries to hide communications.\nIn ESXi environments, adversaries may leverage the Virtual Machine Communication Interface (VMCI) for communication between guest virtual machines and the ESXi host. This traffic is similar to client-server communications on traditional network sockets but is localized to the physical machine running the ESXi host, meaning it does not traverse external networks (routers, switches). This results in communications that are invisible to external monitoring and standard networking tools like tcpdump, netstat, nmap, and Wireshark. By adding a VMCI backdoor to a compromised ESXi host, adversaries may persistently regain access from any guest VM to the compromised ESXi host’s backdoor, regardless of network segmentation or firewall rules in place.",
              "signatures": [
                {
                  "severity": "INFO",
                  "description": "Performs DNS lookups",
                  "match_data": [
                    "DNS query: dns.google"
                  ]
                }
              ]
            },
            {
              "id": "T1071",
              "name": "Application Layer Protocol",
              "link": "https://attack.mitre.org/techniques/T1071/",
              "description": "Adversaries may communicate using OSI application layer protocols to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server. \nAdversaries may utilize many different protocols, including those used for web browsing, transferring files, electronic mail, DNS, or publishing/subscribing. For connections that occur internally within an enclave (such as those between a proxy or pivot node and other nodes), commonly used protocols are SMB, SSH, or RDP. ",
              "signatures": [
                {
                  "severity": "INFO",
                  "description": "Performs DNS lookups",
                  "match_data": [
                    "DNS query: dns.google"
                  ]
                },
                {
                  "severity": "INFO",
                  "description": "Uses HTTPS",
                  "match_data": [
                    "HTTP traffic on port 56717 -> 443",
                    "HTTP traffic on port 56746 -> 443",
                    "HTTP traffic on port 56790 -> 443",
                    "HTTP traffic on port 443 -> 56717",
                    "HTTP traffic on port 56769 -> 443",
                    "HTTP traffic on port 443 -> 56679",
                    "HTTP traffic on port 443 -> 56712",
                    "HTTP traffic on port 443 -> 56796",
                    "HTTP traffic on port 443 -> 56797",
                    "HTTP traffic on port 56586 -> 443",
                    "HTTP traffic on port 56781 -> 443",
                    "HTTP traffic on port 56695 -> 443",
                    "HTTP traffic on port 56778 -> 443",
                    "HTTP traffic on port 56789 -> 443",
                    "HTTP traffic on port 443 -> 56607",
                    "HTTP traffic on port 443 -> 56609",
                    "HTTP traffic on port 56793 -> 443",
                    "HTTP traffic on port 56737 -> 443",
                    "HTTP traffic on port 443 -> 56686",
                    "HTTP traffic on port 443 -> 56687",
                    "HTTP traffic on port 443 -> 56722",
                    "HTTP traffic on port 56712 -> 443",
                    "HTTP traffic on port 443 -> 56695",
                    "HTTP traffic on port 56775 -> 443",
                    "HTTP traffic on port 56761 -> 443",
                    "HTTP traffic on port 56687 -> 443",
                    "HTTP traffic on port 56792 -> 443",
                    "HTTP traffic on port 443 -> 56734",
                    "HTTP traffic on port 56773 -> 443",
                    "HTTP traffic on port 443 -> 56737",
                    "HTTP traffic on port 56734 -> 443",
                    "HTTP traffic on port 443 -> 56610",
                    "HTTP traffic on port 443 -> 56611",
                    "HTTP traffic on port 443 -> 56583",
                    "HTTP traffic on port 56648 -> 443",
                    "HTTP traffic on port 443 -> 56585",
                    "HTTP traffic on port 443 -> 56586",
                    "HTTP traffic on port 56795 -> 443",
                    "HTTP traffic on port 56640 -> 443",
                    "HTTP traffic on port 56787 -> 443",
                    "HTTP traffic on port 56609 -> 443",
                    "HTTP traffic on port 56583 -> 443",
                    "HTTP traffic on port 443 -> 56746",
                    "HTTP traffic on port 443 -> 56747",
                    "HTTP traffic on port 56756 -> 443",
                    "HTTP traffic on port 56708 -> 443",
                    "HTTP traffic on port 56784 -> 443",
                    "HTTP traffic on port 56610 -> 443",
                    "HTTP traffic on port 56742 -> 443",
                    "HTTP traffic on port 56771 -> 443",
                    "HTTP traffic on port 443 -> 56639",
                    "HTTP traffic on port 56788 -> 443",
                    "HTTP traffic on port 56794 -> 443",
                    "HTTP traffic on port 443 -> 56756",
                    "HTTP traffic on port 443 -> 56757",
                    "HTTP traffic on port 56679 -> 443",
                    "HTTP traffic on port 443 -> 56640",
                    "HTTP traffic on port 443 -> 56761",
                    "HTTP traffic on port 56785 -> 443",
                    "HTTP traffic on port 56797 -> 443",
                    "HTTP traffic on port 56722 -> 443",
                    "HTTP traffic on port 56607 -> 443",
                    "HTTP traffic on port 56747 -> 443",
                    "HTTP traffic on port 56768 -> 443",
                    "HTTP traffic on port 443 -> 56768",
                    "HTTP traffic on port 443 -> 56769",
                    "HTTP traffic on port 443 -> 56648",
                    "HTTP traffic on port 56585 -> 443",
                    "HTTP traffic on port 56779 -> 443",
                    "HTTP traffic on port 443 -> 56771",
                    "HTTP traffic on port 443 -> 56773",
                    "HTTP traffic on port 56782 -> 443",
                    "HTTP traffic on port 56639 -> 443",
                    "HTTP traffic on port 56796 -> 443",
                    "HTTP traffic on port 443 -> 56778",
                    "HTTP traffic on port 56786 -> 443",
                    "HTTP traffic on port 443 -> 56779",
                    "HTTP traffic on port 443 -> 56774",
                    "HTTP traffic on port 443 -> 56775",
                    "HTTP traffic on port 443 -> 56781",
                    "HTTP traffic on port 443 -> 56782",
                    "HTTP traffic on port 443 -> 56784",
                    "HTTP traffic on port 56757 -> 443",
                    "HTTP traffic on port 443 -> 56780",
                    "HTTP traffic on port 56611 -> 443",
                    "HTTP traffic on port 56686 -> 443",
                    "HTTP traffic on port 56791 -> 443",
                    "HTTP traffic on port 443 -> 56708",
                    "HTTP traffic on port 443 -> 56789",
                    "HTTP traffic on port 56774 -> 443",
                    "HTTP traffic on port 443 -> 56785",
                    "HTTP traffic on port 443 -> 56786",
                    "HTTP traffic on port 443 -> 56787",
                    "HTTP traffic on port 443 -> 56788",
                    "HTTP traffic on port 56780 -> 443",
                    "HTTP traffic on port 443 -> 56792",
                    "HTTP traffic on port 443 -> 56793",
                    "HTTP traffic on port 443 -> 56794",
                    "HTTP traffic on port 443 -> 56795",
                    "HTTP traffic on port 443 -> 56790",
                    "HTTP traffic on port 443 -> 56791"
                  ]
                }
              ]
            }
          ]
        }
      ]
    },
    "Zenbox": {
      "tactics": [
        {
          "id": "TA0003",
          "name": "Persistence",
          "link": "https://attack.mitre.org/tactics/TA0003/",
          "description": "The adversary is trying to maintain their foothold.\n\nPersistence consists of techniques that adversaries use to keep access to systems across restarts, changed credentials, and other interruptions that could cut off their access. Techniques used for persistence include any access, action, or configuration changes that let them maintain their foothold on systems, such as replacing or hijacking legitimate code or adding startup code. ",
          "techniques": [
            {
              "id": "T1176",
              "name": "Software Extensions",
              "link": "https://attack.mitre.org/techniques/T1176/",
              "description": "Adversaries may abuse software extensions to establish persistent access to victim systems. Software extensions are modular components that enhance or customize the functionality of software applications, including web browsers, Integrated Development Environments (IDEs), and other platforms. Extensions are typically installed via official marketplaces, app stores, or manually loaded by users, and they often inherit the permissions and access levels of the host application. \nMalicious extensions can be introduced through various methods, including social engineering, compromised marketplaces, or direct installation by users or by adversaries who have already gained access to a system. Malicious extensions can be named similarly or identically to benign extensions in marketplaces. Security mechanisms in extension marketplaces may be insufficient to detect malicious components, allowing adversaries to bypass automated scanners or exploit trust established during the installation process. Adversaries may also abuse benign extensions to achieve their objectives, such as using legitimate functionality to tunnel data or bypass security controls. \nThe modular nature of extensions and their integration with host applications make them an attractive target for adversaries seeking to exploit trusted software ecosystems. Detection can be challenging due to the inherent trust placed in extensions during installation and their ability to blend into normal application workflows. ",
              "signatures": [
                {
                  "severity": "INFO",
                  "description": "Installs a chrome extension",
                  "match_data": [
                    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe \"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --load-extension=C:\\chrome"
                  ]
                }
              ]
            },
            {
              "id": "T1574",
              "name": "Hijack Execution Flow",
              "link": "https://attack.mitre.org/techniques/T1574/",
              "description": "Adversaries may execute their own malicious payloads by hijacking the way operating systems run programs. Hijacking execution flow can be for the purposes of persistence, since this hijacked execution may reoccur over time. Adversaries may also use these mechanisms to elevate privileges or evade defenses, such as application control or other restrictions on execution.\nThere are many ways an adversary may hijack the flow of execution, including by manipulating how the operating system locates programs to be executed. How the operating system locates libraries to be used by a program can also be intercepted. Locations where the operating system looks for programs/resources, such as file directories and in the case of Windows the Registry, could also be poisoned to include malicious payloads."
            },
            {
              "id": "T1574.002",
              "name": "DLL Side-Loading",
              "link": "https://attack.mitre.org/techniques/T1574/002/",
              "description": "Adversaries may execute their own malicious payloads by side-loading DLLs. Similar to DLL, side-loading involves hijacking which DLL a program loads. But rather than just planting the DLL within the search order of a program then waiting for the victim application to be invoked, adversaries may directly side-load their payloads by planting then invoking a legitimate application that executes their payload(s).\nSide-loading takes advantage of the DLL search order used by the loader by positioning both the victim application and malicious payload(s) alongside each other. Adversaries likely use side-loading as a means of masking actions they perform under a legitimate, trusted, and potentially elevated system or software process. Benign executables used to side-load payloads may not be flagged during delivery and/or execution. Adversary payloads may also be encrypted/packed or otherwise obfuscated until loaded into the memory of the trusted process.",
              "signatures": [
                {
                  "severity": "INFO",
                  "description": "Tries to load missing DLLs",
                  "match_data": [
                    "7z.dll",
                    "kernel.appcore.dll",
                    "windows.staterepositorycore.dll",
                    "windows.storage.dll",
                    "wintypes.dll",
                    "appextension.dll",
                    "windows.staterepositoryps.dll",
                    "windows.applicationmodel.dll",
                    "windows.staterepositoryclient.dll",
                    "windows.staterepositorybroker.dll",
                    "appxdeploymentclient.dll",
                    "bcrypt.dll",
                    "rometadata.dll",
                    "mrmcorer.dll",
                    "iertutil.dll",
                    "profapi.dll",
                    "bcp47mrm.dll",
                    "windows.ui.dll",
                    "uxtheme.dll",
                    "propsys.dll",
                    "windows.system.launcher.dll",
                    "msvcp110_win.dll",
                    "twinapi.appcore.dll",
                    "windows.globalization.dll",
                    "bcp47langs.dll",
                    "windows.web.dll",
                    "cryptowinrt.dll",
                    "ncrypt.dll",
                    "ntasn1.dll",
                    "mskeyprotect.dll",
                    "dpapi.dll",
                    "cryptbase.dll",
                    "ntmarta.dll",
                    "coremessaging.dll"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "TA0004",
          "name": "Privilege Escalation",
          "link": "https://attack.mitre.org/tactics/TA0004/",
          "description": "The adversary is trying to gain higher-level permissions.\n\nPrivilege Escalation consists of techniques that adversaries use to gain higher-level permissions on a system or network. Adversaries can often enter and explore a network with unprivileged access but require elevated permissions to follow through on their objectives. Common approaches are to take advantage of system weaknesses, misconfigurations, and vulnerabilities. Examples of elevated access include: \n\n* SYSTEM/root level\n* local administrator\n* user account with admin-like access \n* user accounts with access to specific system or perform specific function\n\nThese techniques often overlap with Persistence techniques, as OS features that let an adversary persist can execute in an elevated context.  ",
          "techniques": [
            {
              "id": "T1574",
              "name": "Hijack Execution Flow",
              "link": "https://attack.mitre.org/techniques/T1574/",
              "description": "Adversaries may execute their own malicious payloads by hijacking the way operating systems run programs. Hijacking execution flow can be for the purposes of persistence, since this hijacked execution may reoccur over time. Adversaries may also use these mechanisms to elevate privileges or evade defenses, such as application control or other restrictions on execution.\nThere are many ways an adversary may hijack the flow of execution, including by manipulating how the operating system locates programs to be executed. How the operating system locates libraries to be used by a program can also be intercepted. Locations where the operating system looks for programs/resources, such as file directories and in the case of Windows the Registry, could also be poisoned to include malicious payloads."
            },
            {
              "id": "T1574.002",
              "name": "DLL Side-Loading",
              "link": "https://attack.mitre.org/techniques/T1574/002/",
              "description": "Adversaries may execute their own malicious payloads by side-loading DLLs. Similar to DLL, side-loading involves hijacking which DLL a program loads. But rather than just planting the DLL within the search order of a program then waiting for the victim application to be invoked, adversaries may directly side-load their payloads by planting then invoking a legitimate application that executes their payload(s).\nSide-loading takes advantage of the DLL search order used by the loader by positioning both the victim application and malicious payload(s) alongside each other. Adversaries likely use side-loading as a means of masking actions they perform under a legitimate, trusted, and potentially elevated system or software process. Benign executables used to side-load payloads may not be flagged during delivery and/or execution. Adversary payloads may also be encrypted/packed or otherwise obfuscated until loaded into the memory of the trusted process.",
              "signatures": [
                {
                  "severity": "INFO",
                  "description": "Tries to load missing DLLs",
                  "match_data": [
                    "7z.dll",
                    "kernel.appcore.dll",
                    "windows.staterepositorycore.dll",
                    "windows.storage.dll",
                    "wintypes.dll",
                    "appextension.dll",
                    "windows.staterepositoryps.dll",
                    "windows.applicationmodel.dll",
                    "windows.staterepositoryclient.dll",
                    "windows.staterepositorybroker.dll",
                    "appxdeploymentclient.dll",
                    "bcrypt.dll",
                    "rometadata.dll",
                    "mrmcorer.dll",
                    "iertutil.dll",
                    "profapi.dll",
                    "bcp47mrm.dll",
                    "windows.ui.dll",
                    "uxtheme.dll",
                    "propsys.dll",
                    "windows.system.launcher.dll",
                    "msvcp110_win.dll",
                    "twinapi.appcore.dll",
                    "windows.globalization.dll",
                    "bcp47langs.dll",
                    "windows.web.dll",
                    "cryptowinrt.dll",
                    "ncrypt.dll",
                    "ntasn1.dll",
                    "mskeyprotect.dll",
                    "dpapi.dll",
                    "cryptbase.dll",
                    "ntmarta.dll",
                    "coremessaging.dll"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "TA0005",
          "name": "Defense Evasion",
          "link": "https://attack.mitre.org/tactics/TA0005/",
          "description": "The adversary is trying to avoid being detected.\n\nDefense Evasion consists of techniques that adversaries use to avoid detection throughout their compromise. Techniques used for defense evasion include uninstalling/disabling security software or obfuscating/encrypting data and scripts. Adversaries also leverage and abuse trusted processes to hide and masquerade their malware. Other tactics’ techniques are cross-listed here when those techniques include the added benefit of subverting defenses. ",
          "techniques": [
            {
              "id": "T1574",
              "name": "Hijack Execution Flow",
              "link": "https://attack.mitre.org/techniques/T1574/",
              "description": "Adversaries may execute their own malicious payloads by hijacking the way operating systems run programs. Hijacking execution flow can be for the purposes of persistence, since this hijacked execution may reoccur over time. Adversaries may also use these mechanisms to elevate privileges or evade defenses, such as application control or other restrictions on execution.\nThere are many ways an adversary may hijack the flow of execution, including by manipulating how the operating system locates programs to be executed. How the operating system locates libraries to be used by a program can also be intercepted. Locations where the operating system looks for programs/resources, such as file directories and in the case of Windows the Registry, could also be poisoned to include malicious payloads."
            },
            {
              "id": "T1574.002",
              "name": "DLL Side-Loading",
              "link": "https://attack.mitre.org/techniques/T1574/002/",
              "description": "Adversaries may execute their own malicious payloads by side-loading DLLs. Similar to DLL, side-loading involves hijacking which DLL a program loads. But rather than just planting the DLL within the search order of a program then waiting for the victim application to be invoked, adversaries may directly side-load their payloads by planting then invoking a legitimate application that executes their payload(s).\nSide-loading takes advantage of the DLL search order used by the loader by positioning both the victim application and malicious payload(s) alongside each other. Adversaries likely use side-loading as a means of masking actions they perform under a legitimate, trusted, and potentially elevated system or software process. Benign executables used to side-load payloads may not be flagged during delivery and/or execution. Adversary payloads may also be encrypted/packed or otherwise obfuscated until loaded into the memory of the trusted process.",
              "signatures": [
                {
                  "severity": "INFO",
                  "description": "Tries to load missing DLLs",
                  "match_data": [
                    "7z.dll",
                    "kernel.appcore.dll",
                    "windows.staterepositorycore.dll",
                    "windows.storage.dll",
                    "wintypes.dll",
                    "appextension.dll",
                    "windows.staterepositoryps.dll",
                    "windows.applicationmodel.dll",
                    "windows.staterepositoryclient.dll",
                    "windows.staterepositorybroker.dll",
                    "appxdeploymentclient.dll",
                    "bcrypt.dll",
                    "rometadata.dll",
                    "mrmcorer.dll",
                    "iertutil.dll",
                    "profapi.dll",
                    "bcp47mrm.dll",
                    "windows.ui.dll",
                    "uxtheme.dll",
                    "propsys.dll",
                    "windows.system.launcher.dll",
                    "msvcp110_win.dll",
                    "twinapi.appcore.dll",
                    "windows.globalization.dll",
                    "bcp47langs.dll",
                    "windows.web.dll",
                    "cryptowinrt.dll",
                    "ncrypt.dll",
                    "ntasn1.dll",
                    "mskeyprotect.dll",
                    "dpapi.dll",
                    "cryptbase.dll",
                    "ntmarta.dll",
                    "coremessaging.dll"
                  ]
                }
              ]
            },
            {
              "id": "T1036",
              "name": "Masquerading",
              "link": "https://attack.mitre.org/techniques/T1036/",
              "description": "Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign to users and/or security tools. Masquerading occurs when the name or location of an object, legitimate or malicious, is manipulated or abused for the sake of evading defenses and observation. This may include manipulating file metadata, tricking users into misidentifying the file type, and giving legitimate task or service names.\nRenaming abusable system utilities to evade security monitoring is also a form of Masquerading.",
              "signatures": [
                {
                  "severity": "INFO",
                  "description": "Creates files inside the user directory",
                  "match_data": [
                    "C:\\Users\\user\\AppData\\Local\\Packages\\Microsoft.WidgetsPlatformRuntime_8wekyb3d8bbwe\\LocalState\\FeedSessions\\MicrosoftWindows.Client.WebExperience_cw5n1h2txyewy!Widgets!!com.msn.desktopfeed"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "TA0007",
          "name": "Discovery",
          "link": "https://attack.mitre.org/tactics/TA0007/",
          "description": "The adversary is trying to figure out your environment.\n\nDiscovery consists of techniques an adversary may use to gain knowledge about the system and internal network. These techniques help adversaries observe the environment and orient themselves before deciding how to act. They also allow adversaries to explore what they can control and what’s around their entry point in order to discover how it could benefit their current objective. Native operating system tools are often used toward this post-compromise information-gathering objective. ",
          "techniques": [
            {
              "id": "T1082",
              "name": "System Information Discovery",
              "link": "https://attack.mitre.org/techniques/T1082/",
              "description": "An adversary may attempt to get detailed information about the operating system and hardware, including version, patches, hotfixes, service packs, and architecture. Adversaries may use this information to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions. This behavior is distinct from Local Storage Discovery which is an adversary's discovery of local drive, disks and/or volumes.\nTools such as Systeminfo can be used to gather detailed system information. If running with privileged access, a breakdown of system data can be gathered through the systemsetup configuration tool on macOS. Adversaries may leverage a Network Device CLI on network devices to gather detailed system information (e.g. show version). On ESXi servers, threat actors may gather system information from various esxcli utilities, such as system hostname get and system version get.\nInfrastructure as a Service (IaaS) cloud providers such as AWS, GCP, and Azure allow access to instance and virtual machine information via APIs. Successful authenticated API calls can return data such as the operating system platform and status of a particular instance or the model view of a virtual machine.\nSystem Information Discovery combined with information gathered from other forms of discovery and reconnaissance can drive payload development and concealment. ",
              "signatures": [
                {
                  "severity": "INFO",
                  "description": "Reads software policies",
                  "match_data": [
                    "HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "TA0009",
          "name": "Collection",
          "link": "https://attack.mitre.org/tactics/TA0009/",
          "description": "The adversary is trying to gather data of interest to their goal.\n\nCollection consists of techniques adversaries may use to gather information and the sources information is collected from that are relevant to following through on the adversary's objectives. Frequently, the next goal after collecting data is to either steal (exfiltrate) the data or to use the data to gain more information about the target environment. Common target sources include various drive types, browsers, audio, video, and email. Common collection methods include capturing screenshots and keyboard input.",
          "techniques": [
            {
              "id": "T1185",
              "name": "Browser Session Hijacking",
              "link": "https://attack.mitre.org/techniques/T1185/",
              "description": "Adversaries may take advantage of security vulnerabilities and inherent functionality in browser software to change content, modify user-behaviors, and intercept information as part of various browser session hijacking techniques.\nA specific example is when an adversary injects software into a browser that allows them to inherit cookies, HTTP sessions, and SSL client certificates of a user then use the browser as a way to pivot into an authenticated intranet. Executing browser-based behaviors such as pivoting may require specific process permissions, such as SeDebugPrivilege and/or high-integrity/administrator rights.\nAnother example involves pivoting browser traffic from the adversary's browser through the user's browser by setting up a proxy which will redirect web traffic. This does not alter the user's traffic in any way, and the proxy connection can be severed as soon as the browser is closed. The adversary assumes the security context of whichever browser process the proxy is injected into. Browsers typically create a new process for each tab that is opened and permissions and certificates are separated accordingly. With these permissions, an adversary could potentially browse to any resource on an intranet, such as Sharepoint or webmail, that is accessible through the browser and which the browser has sufficient permissions. Browser pivoting may also bypass security provided by 2-factor authentication.",
              "signatures": [
                {
                  "severity": "INFO",
                  "description": "Installs a chrome extension",
                  "match_data": [
                    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe \"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --load-extension=C:\\chrome"
                  ]
                }
              ]
            }
          ]
        },
        {
          "id": "TA0011",
          "name": "Command and Control",
          "link": "https://attack.mitre.org/tactics/TA0011/",
          "description": "The adversary is trying to communicate with compromised systems to control them.\n\nCommand and Control consists of techniques that adversaries may use to communicate with systems under their control within a victim network. Adversaries commonly attempt to mimic normal, expected traffic to avoid detection. There are many ways an adversary can establish command and control with various levels of stealth depending on the victim’s network structure and defenses.",
          "techniques": [
            {
              "id": "T1573",
              "name": "Encrypted Channel",
              "link": "https://attack.mitre.org/techniques/T1573/",
              "description": "Adversaries may employ an encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol. Despite the use of a secure algorithm, these implementations may be vulnerable to reverse engineering if secret keys are encoded and/or generated within malware samples/configuration files.",
              "signatures": [
                {
                  "severity": "INFO",
                  "description": "Uses HTTPS for network communication, use the SSL MITM Proxy cookbook for further analysis"
                },
                {
                  "severity": "INFO",
                  "description": "Uses HTTPS",
                  "match_data": [
                    "HTTP traffic on port 443 -> 49722",
                    "HTTP traffic on port 443 -> 49744",
                    "HTTP traffic on port 49734 -> 443",
                    "HTTP traffic on port 443 -> 49743",
                    "HTTP traffic on port 443 -> 49742",
                    "HTTP traffic on port 49742 -> 443",
                    "HTTP traffic on port 49743 -> 443",
                    "HTTP traffic on port 49744 -> 443",
                    "HTTP traffic on port 49722 -> 443",
                    "HTTP traffic on port 443 -> 49739",
                    "HTTP traffic on port 443 -> 49737",
                    "HTTP traffic on port 49737 -> 443",
                    "HTTP traffic on port 443 -> 49734",
                    "HTTP traffic on port 49739 -> 443"
                  ]
                }
              ]
            },
            {
              "id": "T1095",
              "name": "Non-Application Layer Protocol",
              "link": "https://attack.mitre.org/techniques/T1095/",
              "description": "Adversaries may use an OSI non-application layer protocol for communication between host and C2 server or among infected hosts within a network. The list of possible protocols is extensive. Specific examples include use of network layer protocols, such as the Internet Control Message Protocol (ICMP), transport layer protocols, such as the User Datagram Protocol (UDP), session layer protocols, such as Socket Secure (SOCKS), as well as redirected/tunneled protocols, such as Serial over LAN (SOL).\nICMP communication between hosts is one example. Because ICMP is part of the Internet Protocol Suite, it is required to be implemented by all IP-compatible hosts. However, it is not as commonly monitored as other Internet Protocols such as TCP or UDP and may be used by adversaries to hide communications.\nIn ESXi environments, adversaries may leverage the Virtual Machine Communication Interface (VMCI) for communication between guest virtual machines and the ESXi host. This traffic is similar to client-server communications on traditional network sockets but is localized to the physical machine running the ESXi host, meaning it does not traverse external networks (routers, switches). This results in communications that are invisible to external monitoring and standard networking tools like tcpdump, netstat, nmap, and Wireshark. By adding a VMCI backdoor to a compromised ESXi host, adversaries may persistently regain access from any guest VM to the compromised ESXi host’s backdoor, regardless of network segmentation or firewall rules in place.",
              "signatures": [
                {
                  "severity": "INFO",
                  "description": "Performs DNS lookups",
                  "match_data": [
                    "DNS query: c.pki.goog",
                    "DNS query: www.google.com",
                    "DNS query: themesforytextension.com",
                    "DNS query: ogads-pa.clients6.google.com",
                    "DNS query: apis.google.com",
                    "DNS query: play.google.com",
                    "DNS query: chrome.google.com"
                  ]
                }
              ]
            },
            {
              "id": "T1071",
              "name": "Application Layer Protocol",
              "link": "https://attack.mitre.org/techniques/T1071/",
              "description": "Adversaries may communicate using OSI application layer protocols to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server. \nAdversaries may utilize many different protocols, including those used for web browsing, transferring files, electronic mail, DNS, or publishing/subscribing. For connections that occur internally within an enclave (such as those between a proxy or pivot node and other nodes), commonly used protocols are SMB, SSH, or RDP. ",
              "signatures": [
                {
                  "severity": "INFO",
                  "description": "Performs DNS lookups",
                  "match_data": [
                    "DNS query: c.pki.goog",
                    "DNS query: www.google.com",
                    "DNS query: themesforytextension.com",
                    "DNS query: ogads-pa.clients6.google.com",
                    "DNS query: apis.google.com",
                    "DNS query: play.google.com",
                    "DNS query: chrome.google.com"
                  ]
                },
                {
                  "severity": "INFO",
                  "description": "Uses HTTPS",
                  "match_data": [
                    "HTTP traffic on port 443 -> 49722",
                    "HTTP traffic on port 443 -> 49744",
                    "HTTP traffic on port 49734 -> 443",
                    "HTTP traffic on port 443 -> 49743",
                    "HTTP traffic on port 443 -> 49742",
                    "HTTP traffic on port 49742 -> 443",
                    "HTTP traffic on port 49743 -> 443",
                    "HTTP traffic on port 49744 -> 443",
                    "HTTP traffic on port 49722 -> 443",
                    "HTTP traffic on port 443 -> 49739",
                    "HTTP traffic on port 443 -> 49737",
                    "HTTP traffic on port 49737 -> 443",
                    "HTTP traffic on port 443 -> 49734",
                    "HTTP traffic on port 49739 -> 443"
                  ]
                }
              ]
            }
          ]
        }
      ]
    }
  },
  "links": {
    "self": "https://www.virustotal.com/api/v3/files/0efc314b1b7f6c74e772eb1f8f207ed50c2e702aed5e565081cbcf8f28f0fe26/behaviour_mitre_trees"
  }
}
}


"""
