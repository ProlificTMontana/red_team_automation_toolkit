# Red Team Automation Toolkit

## Overview
The Red Team Automation Toolkit is designed to streamline and automate common red team operations, including network reconnaissance, vulnerability exploitation, and payload delivery. The toolkit features a user-friendly menu-driven interface built with Streamlit and integrates popular tools like Nmap, Metasploit RPC, and Empire.

## Features
- Menu-driven interface for easy task selection
- Modular task runners for scanning, exploitation, and payload delivery
- OPSEC-friendly logging to avoid sensitive data exposure
- Extensible architecture to add more modules in the future
- Runs on Python with minimal dependencies

## Technology Stack
- Python 3.8+
- Streamlit for the UI
- Nmap for network scanning (needs to be installed separately)
- Integration stubs for Metasploit RPC and Empire (for exploitation and payload delivery)

## Installation
1. Clone the repository:

```bash
git clone https://github.com/ProlificTMontana/red_team_automation_toolkit.git
cd red_team_automation_toolkit
```
2. Set up a Python virtual environment (recommended):

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```
3. Install Python dependencies:

```bash
pip install -r requirements.txt
```
4. Make sure Nmap is installed on your system and its executable is in your PATH.
5. Run the application:

```bash
python -m streamlit run app.py
```

## Usage

- Select the desired task from the sidebar menu.
- Provide required inputs such as targets, module names, or options depending on the task.
- Run the task and view the results/logs in the interface.

## Notes

- Metasploit RPC and Empire integration methods are stubbed and need to be implemented according to your environment.
- Logging is designed for OPSEC to avoid sensitive information leakage.
- Customize Nmap arguments and module options as needed.


