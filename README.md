# autoRecon
A simple script that automates basic pentester reconnaissance starting from Nmap scans.

Ideally used in internal Pentets where the scope is very limited and time is very limited. Also the organization should not pick up internal scanning :)

It does the following:
*Runs 3 different basic nmap scans to find UP hosts
*Collates UP hosts
*Runs top 2000 ports Scan

Flag for Exhaustive Runs:
* Full port scan
* Common Web ports scan and Eyewitness on web ports found
* SMB ports scan and runs Enum4Linux on smb ports found.


Runs on Kali and Linux with The Penetesters Framework(PTF) installed using the /pentest directory as the base.