======================================================================
         SCAPY ENVIRONMENT SETUP & EXECUTION GUIDE (FIRST TIME USE)
======================================================================

Follow these instructions in order inside  Linux Virtual Machine 
Terminal (Ctrl + Alt + T) to set up and run the network script.

----------------------------------------------------------------------
PHASE 1: FIRST-TIME INSTALLATION & INITIAL SETUP
----------------------------------------------------------------------
Run these commands one by one to configure  Python environment 
and install Scapy dependencies on the Linux filesystem.

1. Update system packages and install Python environment tools:
   sudo apt update && sudo apt install python3-venv python3-pip -y

2. Move to  home directory:
   cd ~

3. Create a clean virtual environment named 'scapy-env':
   python3 -m venv scapy-env

4. Activate the virtual environment workspace:
   source ~/scapy-env/bin/activate
   (Note:  terminal line will now start with '(scapy-env)')

5. Navigate to  shared project folder:
   cd /media/sf_spoofing_code

6. Upgrade pip and install Scapy along with  script dependencies:
   pip install --upgrade pip
   pip install scapy
   pip install -r requirements.txt

7. Grant  user account permissions to read the shared folder files:
   sudo usermod -aG vboxsf $USER

CRUCIAL STEP: Now, RESTART  Virtual Machine so the shared folder 
permissions can take effect.

----------------------------------------------------------------------
PHASE 2: HOW TO RUN  CODE (DAILY USE PRESETS)
----------------------------------------------------------------------
Once the installation is complete, use these steps every time you 
boot up  VM to execute  attack or sniffer scripts.

1. Open  terminal (Ctrl + Alt + T).

2. Switch to  project code folder:
   cd /media/sf_spoofing_code

3. Run  script with full administrative root privileges:
   sudo /home/osboxes/scapy-env/bin/python main.py

----------------------------------------------------------------------
TROUBLESHOOTING NOTES:
----------------------------------------------------------------------
* To STOP the script from running at any time: Press 'Ctrl + C'.
* If asked for a password after typing 'sudo': Type  Linux user 
  password (e.g., 'osboxes') and press Enter. The characters will not 
  show on the screen while you type.
* Do NOT create or run the virtual environment folders inside the 
  /media/ directory, as the shared Windows filesystem will corrupt 
  the Python internal binaries. Keep the environment inside 'cd ~'.
======================================================================
