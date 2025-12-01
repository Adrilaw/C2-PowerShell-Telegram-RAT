# ELIANA-Remote-Acces-Trojan

A PowerShell-based Command-and-Control tool designed for **authorized Vulnerability Assessment & Penetration Testing (VAPT)** engagements.  
This tool enables security testers with explicit permission to remotely execute commands, collect system information, and perform surveillance through a Telegram Bot interface.

<img width="413" height="584" alt="Image" src="https://github.com/user-attachments/assets/dd105739-85e3-4ab4-ba3e-79b6ae55e377" />


# ⚙️ Setup Instructions for ELIANA.py Script

## ⚙️ Complete Command List

# Basic System Commands
`sessionid ls`                       # List directory contents  

`sessionid pwd`                     # Show current directory  

`sessionid whoami`                   # Show current user context 

`sessionid ps`                       # List running processes  

`sessionid netstat`                   # Show network connections  

`sessionid sysinfo`                   # Get system information  

# Surveillance & Recording 
`sessionid screenshot`                # Capture screen and upload  

`sessionid record-audio` [sec]        # Record audio (e.g., record-audio 10)  

`sessionid screen-record` [sec]       # Record screen (e.g., screen-record 10)


# Data Collection
`sessionid download` [file_path]      # Upload file from target to C2  

`sessionid upload` [URL] [dest]        # Download file from URL to target  

# Persistance & Management
`sessionid persist`                  # Install multi-method persistence (survives reboot)  

`sessionid unpersist`                # Remove all persistence methods  

`sessionid exit`                     # Terminate C2 session  

# Custom Commands
`sessioid [any powershell]`          # Execute any PowerShell command

`sessioid ALL [command]`             # Execute on all active sessions


✨ Key Features

✅ True Persistence - Survives reboot via Registry, Scheduled Tasks, and Startup folder

✅ Complete Surveillance - Screenshots, audio recording, webcam capture, screen recording

✅ Credential Harvesting - Chromium browser detection and data extraction

✅ File Operations - Upload/download files without disk writes

✅ Stealthy - Fileless operations, jittered beacons, history protection

✅ Reliable - Multiple fallback methods for all operations


# ✍🏼 About Author

I'm Dodin Mel-Adrien also known as Kidpentester/Adrilaw built this as an intern , to demonstrate the use of telegram to gain access to a windows machine without being detected by antivirus software , this tool was explicitly designed for vulnerability assesment and penetration testing . My inspiration to build this came from my wife , she inspired me in a way I can’t fully describe. Her strength, beauty, and resilience showed me what it means to keep moving forward no matter what stands in the way. Watching how she never let anything break her spirit made me want to push myself harder, to build things, to improve my skills, and to create tools that help me grow in my cybersecurity journey. Her character reminded me that when someone is strong and unstoppable, you feel motivated to chase your goals with the same energy. 

# Credits

🔥 https://github.com/FebVeg/TGRS

🔥 https://github.com/gunzf0x/BypassAMSI_PSRevshell

# License
ELIANA-Remote-Acces-Trojan is licensed under the [GNU General Public License](LICENSE) and the [ELIANA-Remote-Acces-Trojan Commercial License](C-LICENSE)- see the LICENSE file for details.

⚠️ Legal & Ethical Notice

This tool is strictly for use in authorized security assessments with explicit written permission.
Unauthorized use, including but not limited to surveillance, credential harvesting, or persistence installation, is illegal and unethical.
Use responsibly and always operate within your legal boundaries.
