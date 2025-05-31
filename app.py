import streamlit as st
import subprocess
import json
import logging
from datetime import datetime
import base64

# Set page configuration at the top
st.set_page_config(
    page_title="Red Team Automation Toolkit",
    layout="wide",
    initial_sidebar_state="expanded"
)

# OPSEC-friendly logger setup
logger = logging.getLogger('redteam_toolkit')
logger.setLevel(logging.INFO)
# File handler with daily logs
log_filename = f"redteam_toolkit_{datetime.now().strftime('%Y-%m-%d')}.log"
file_handler = logging.FileHandler(log_filename)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# Hide Streamlit menu and footer for cleaner UI
hide_streamlit_style = """
            <style>
            #MainMenu {visibility: hidden;}
            footer {visibility: hidden;}
            </style>
            """
st.markdown(hide_streamlit_style, unsafe_allow_html=True)

st.title("🚩 Red Team Automation Toolkit")
st.write(
    """
    Automate common red team tasks like scanning, exploitation, 
    and payload delivery with OPSEC-friendly logging.
    """
)

# ------------- Helper Functions -------------

def opsec_log(message):
    # Log only essential info without sensitive details
    logger.info(message)

def run_nmap_scan(target, arguments):
    """
    Run an Nmap scan using subprocess and capture results.
    """
    try:
        cmd = f"nmap {arguments} {target} -oX -"
        opsec_log(f"Nmap scan started on target: {target} with arguments: {arguments}")
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            opsec_log(f"Nmap scan failed: {result.stderr.strip()}")
            return None, f"Nmap scan error: {result.stderr.strip()}"
        opsec_log(f"Nmap scan completed successfully for target: {target}")
        return result.stdout, None
    except subprocess.TimeoutExpired:
        opsec_log(f"Nmap scan timed out for target: {target}")
        return None, "Nmap scan timed out."
    except Exception as e:
        opsec_log(f"Nmap scan exception: {str(e)}")
        return None, str(e)

def msfrpc_execute(module, options):
    """
    Stub for Metasploit RPC API call to execute a module with options.
    Replace with actual RPC calls as needed.
    """
    # Example logging for call
    opsec_log(f"Metasploit RPC execute module: {module} with options keys: {list(options.keys())}")
    # Stubbing response
    return {
        "status": "success",
        "module": module,
        "options": options,
        "message": "Module executed (stub)"
    }

def empire_execute_command(command, args):
    """
    Stub for Empire API call to execute a command with arguments.
    Replace with actual Empire API calls as needed.
    """
    opsec_log(f"Empire execute command: {command} with args: {args}")
    # Stubbing response
    return {
        "status": "success",
        "command": command,
        "args": args,
        "message": "Command executed (stub)"
    }

# ------------- Task Runners -------------

def nmap_task():
    st.header("🕵️ Nmap Scanning")
    target = st.text_input("Target IP or Domain", placeholder="e.g., 192.168.1.1 or example.com")
    arguments = st.text_input("Nmap Arguments", value="-sV -T4")
    
    if st.button("Run Nmap Scan"):
        if not target.strip():
            st.error("Please enter a valid target.")
            return
        with st.spinner("Running Nmap scan..."):
            scan_output, error = run_nmap_scan(target.strip(), arguments.strip())
            if error:
                st.error(error)
            else:
                st.success("Nmap scan completed.")
                # Show raw XML output and offer to download
                st.text_area("Nmap Scan XML Output", value=scan_output, height=300)
                b64 = base64.b64encode(scan_output.encode()).decode()
                href = f'<a href="data:file/xml;base64,{b64}" download="nmap_scan.xml">Download XML Result</a>'
                st.markdown(href, unsafe_allow_html=True)

def metasploit_task():
    st.header("💥 Metasploit Exploitation")
    
    module = st.text_input("Module Path", placeholder="e.g., exploit/windows/smb/ms17_010_eternalblue")
    raw_options = st.text_area("Module Options (JSON)", value='{"RHOSTS": "192.168.1.100", "PAYLOAD": "windows/meterpreter/reverse_tcp"}')
    
    if st.button("Run Metasploit Module"):
        if not module.strip():
            st.error("Module path cannot be empty.")
            return
        try:
            options = json.loads(raw_options)
        except json.JSONDecodeError as e:
            st.error(f"Invalid JSON for options: {str(e)}")
            return
        with st.spinner("Executing Metasploit module..."):
            result = msfrpc_execute(module.strip(), options)
            st.success("Metasploit RPC call completed.")
            st.json(result)

def empire_task():
    st.header("🦅 Empire Payload Delivery")
    
    command = st.text_input("Empire Command", placeholder="e.g., launch")
    args = st.text_area("Command Arguments (JSON)", value='{"Listener": "http"}')
    
    if st.button("Execute Empire Command"):
        if not command.strip():
            st.error("Command cannot be empty.")
            return
        try:
            args_dict = json.loads(args)
        except json.JSONDecodeError as e:
            st.error(f"Invalid JSON for arguments: {str(e)}")
            return
        with st.spinner("Executing Empire command..."):
            result = empire_execute_command(command.strip(), args_dict)
            st.success("Empire command executed.")
            st.json(result)

# ------------- Main Menu -------------

def main():
    menu = [
        "Nmap Scanning",
        "Metasploit Exploitation",
        "Empire Payload Delivery",
        "About"
    ]
    choice = st.sidebar.selectbox("Select Task", menu)
    opsec_log(f"User  selected menu item: {choice}")

    if choice == "Nmap Scanning":
        nmap_task()
    elif choice == "Metasploit Exploitation":
        metasploit_task()
    elif choice == "Empire Payload Delivery":
        empire_task()
    elif choice == "About":
        st.header("About Red Team Automation Toolkit")
        st.markdown("""
        **Stack:** Python Streamlit + Metasploit RPC + Empire + Nmap  
        **Purpose:** Automate common red team tasks like network scanning, exploitation, and payload delivery  
        **Features:**
        - Menu-driven interface with modular task runners
        - OPSEC-friendly logging (logs without sensitive data)
        - Extensible architecture for incorporating new modules  
        
        Developed as an open automation platform for red team operators.
        """)
    else:
        st.write("Select a task from the menu.")

if __name__ == "__main__":
    main()

