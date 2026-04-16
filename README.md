**MITRE Caldera \& Splunk Home Lab**



**Overview:**

This project demonstrates a cybersecurity home lab built in VirtualBox using Kali Linux, Windows 10, MITRE Caldera, and Splunk. I used MITRE Caldera to simulate adversary discovery attack against a Windows 10 VM and used Splunk to investigate the resulting Windows Security logs.



**Objective:**

The goal of this lab was to gain hands-on experience with:

\- Adversary emulation using MITRE Caldera

\- Agent deployment with Sandcat

\- Windows event logging

\- Splunk log analysis

\- Detection of suspicious process execution using Event ID 4688



**Lab Environment:**

\- VirtualBox

\- Kali Linux VM

\- Windows 10 VM

\- MITRE Caldera

\- Sandcat agent

\- Splunk Enterprise

\- Windows Event Viewer



**Network Configuration:**

Both VMs were configured with:

\- Adapter 1: NAT (windows)

\- Adapter 2: Host-Only Adapter (kali)



This allowed internet access and communication between the Kali and Windows virtual machines.



**Project Workflow:**

1\. Started the Kali Linux VM and launched MITRE Caldera

2\. Started the Windows 10 VM

3\. Verified network connectivity between the VMs

4\. Deployed the Sandcat agent from Caldera to the Windows VM

5\. Confirmed the Windows agent appeared in Caldera

6\. Created and ran a Discovery adversary operation

7\. Observed executed commands in Caldera

8\. Reviewed Windows Security Event ID 4688 in Event Viewer

9\. Used Splunk to search for suspicious process execution

10\. Created an alert to detect attacker-related processes



**Adversary Simulation:**

For this lab, I used the "Discovery" adversary profile in MITRE Caldera. This simulated reconnaissance activity commonly performed by attackers.



Examples of observed activity included:

\- whoami.exe

\- cmd.exe

\- powershell.exe



**Log Analysis:**

I reviewed Windows Security logs in both Event Viewer and Splunk. My primary focus was "Event ID 4688", which records new process creation.



**Example Splunk Search:**

```spl

index=main EventCode=4688 

(New\_Process\_Name="\*whoami.exe\*" OR New\_Process\_Name="\*powershell.exe\*" OR New\_Process\_Name="\*cmd.exe\*")

| table \_time, New\_Process\_Name, Creator\_Process\_Name

