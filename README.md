# SOC Automation Lab

## 1. Introduction

### 1.1 Overview
The SOC Automation Project aims to create an automated Security Operations Center (SOC) workflow that streamlines event monitoring, alerting, and incident response. By leveraging powerful open-source tools such as Wazuh, Shuffle, and TheHive, this project enhances the efficiency and effectiveness of SOC operations. The project involves setting up a Windows 10 client with Sysmon for detailed event generation, Wazuh for comprehensive event management and alerting, Shuffle for workflow automation, and TheHive for case management and coordinated response actions.

<img width="820" height="1020" alt="SOC Automation Flow" src="https://github.com/user-attachments/assets/7de20d62-233b-4834-b17d-88d792466e0d" />


### 1.2 Purpose and Goals
- **Automate Event Collection and Analysis:** Ensure security events are collected and analyzed in real-time with minimal manual intervention, enabling proactive threat detection and response.
- **Streamline Alerting Process:** Automate the process of generating and forwarding alerts to relevant systems and personnel, reducing response times and minimizing the risk of overlooking critical incidents.
- **Enhance Incident Response Capabilities:** Automate responsive actions to security incidents, improving reaction time, consistency, and effectiveness in mitigating threats.
- **Improve SOC Efficiency:** Reduce the workload on SOC analysts by automating routine tasks, allowing them to focus on high-priority issues and strategic initiatives.

## 2. Prerequisites

### 2.1 Hardware Requirements
- A host machine capable of running multiple virtual machines simultaneously.
- Sufficient CPU, RAM, and disk space to support the VMs and their expected workloads.

### 2.2 Software Requirements
- **VMware Workstation/Fusion:** Industry-standard virtualization platform for creating and managing virtual machines.
- **Windows 10:** The client machine for generating realistic security events and testing the SOC automation workflow.
- **Ubuntu 22.04:** The stable and feature-rich Linux distribution for deploying Wazuh and TheHive.
- **Sysmon:** A powerful Windows system monitoring tool that provides detailed event logging and telemetry.

### 2.3 Tools and Platforms
- **Wazuh:** An open-source, enterprise-grade security monitoring platform that serves as the central point for event collection, analysis, and alerting.
- **Shuffle:** A flexible, open-source security automation platform that handles workflow automation for alert processing and response actions.
- **TheHive:** A scalable, open-source Security Incident Response Platform designed for SOCs to efficiently manage and resolve incidents.
- **VirusTotal:** An online service that analyzes files and URLs to detect various types of malicious content using multiple antivirus engines and scanners.
- **Cloud Services or Additional VMs:** Wazuh and TheHive can be deployed either on cloud infrastructure or additional virtual machines, depending on your resource availability and preferences.

### 2.4 Prior Knowledge
- **Basic Understanding of Virtual Machines:** Familiarity with setting up and managing VMs using VMware or similar virtualization platforms.
- **Basic Linux Command Line Skills:** Ability to perform essential tasks in a Linux environment, such as installing software packages and configuring services.
- **Knowledge of Security Operations and Tools:** Foundational understanding of security monitoring, event logging, and incident response concepts and tools.

## 3. Setup

### 3.1 Step 1: Install and Configure Windows 10 with Sysmon

**3.1.1 Install Windows 10 on VMware:**
 
  <img width="1292" height="841" alt="Specifications" src="https://github.com/user-attachments/assets/b4292412-b708-454b-98a1-289f8a9f2f9f" />


**3.1.2 Download Sysmon:**

   <img width="1277" height="983" alt="Sysmon Web page" src="https://github.com/user-attachments/assets/72bf5caf-bd3e-463c-bf10-9f9bc777b3c2" />


**3.1.3 Download Sysmon configuration files from [Sysmon Modular Config](https://github.com/olafhartong/sysmon-modular):**
<img width="1233" height="943" alt="Pasted image 20240603131815 (1)" src="https://github.com/user-attachments/assets/a37b6885-65dc-4bc9-b42b-aed53c0a85b2" />
<img width="1222" height="832" alt="Sysmon XML" src="https://github.com/user-attachments/assets/bcba1cf8-ecb0-48ae-a206-45387e8e471f" />



**3.1.4 Extract the Sysmon zip file and open PowerShell as an administrator. Navigate to the Sysmon directory extracted from the zip file:**

  <img width="1238" height="375" alt="Sysmon directory" src="https://github.com/user-attachments/assets/593aa604-7fa6-47b3-aa64-66453b62631d" />


**3.1.5 Place the Sysmon configuration file into the Sysmon directory as well.**

**3.1.6 Before installing Sysmon, check if it is already installed on the Windows machine by verifying:**
 
   - Services
   - Event Viewer > Applications and Services Logs > Microsoft > Windows
   - <img width="795" height="551" alt="Pasted image 20240603133433 (1)" src="https://github.com/user-attachments/assets/f66e355c-3f1e-4836-a654-873ae30dd3b0" />


**3.1.7 Since Sysmon is not installed, proceed with the installation using the command:**

```
.\Sysmon64.exe -i .\sysmonconfig.xml
```

  <img width="885" height="349" alt="Sysmon install Conf" src="https://github.com/user-attachments/assets/e9475b1c-2669-4d2a-ae70-27db912a1f97" />


**3.1.8 After a short installation, verify that Sysmon is installed on the system:**

<img width="1911" height="938" alt="Sysmon service" src="https://github.com/user-attachments/assets/eb3f4bb0-93ef-4dff-94b5-2b3d97c4f92a" />
<img width="1920" height="900" alt="Sysmon event viewer" src="https://github.com/user-attachments/assets/78d88f11-2103-4c76-a4d9-ca8a9afe492e" />

With this step, our Windows 10 machine with Sysmon is ready. The next step is setting up Wazuh.

### 3.2 Step 2: Set Up Wazuh Server

**3.2.1 Create a Droplet on DigitalOcean:**
To set up the Wazuh server, we will be using DigitalOcean, a popular cloud service provider. However, you can use any other cloud platform or virtual machines as well. We start by creating a new Droplet from the DigitalOcean menu:

<img width="1473" height="698" alt="Pasted image 20240603215218" src="https://github.com/user-attachments/assets/0bd09962-ebc7-439a-91ca-81841eb93509" />

We select Ubuntu 22.04 as our operating system for the Droplet:
<img width="957" height="390" alt="Pasted image 20240603220120 (1)" src="https://github.com/user-attachments/assets/d4c2314e-3e1c-43c8-b3e4-f29ad9ac4c57" />

We use a root password for authentication and change the Droplet name to "Wazuh", then create the Droplet:

<img width="1207" height="476" alt="Pasted image 20240603220521 (2)" src="https://github.com/user-attachments/assets/deb71ca6-b391-4661-a4c9-112581f609cf" />


**3.2.2 Set Up a Firewall:**
Next, we need to set up a firewall to prevent unauthorized access and external scan spams. From the DigitalOcean menu, go to Networking > Firewall > Create Firewall:

<img width="1217" height="1021" alt="Pasted image 20240603220742 (1)" src="https://github.com/user-attachments/assets/c0d594d5-11b3-4164-b4bc-b00a21858711" />


We modify the inbound rules to allow access only from our own IP address:

<img width="1236" height="419" alt="Pasted image 20240603220920 (1)" src="https://github.com/user-attachments/assets/e8d33402-3419-455d-aa0e-bf550dff544b" />


After setting up the firewall rules, we apply the firewall to our Wazuh Droplet:

<img width="1920" height="891" alt="Wazuh details" src="https://github.com/user-attachments/assets/316e2a59-885c-4ea4-97b9-dbe79eacf4a3" />
Apply firewall settings to Wazuh droplet  
Now our firewall is protecting the Wazuh virtual machine.

**3.2.3 Connect to the Wazuh Server via SSH:**
From the DigitalOcean left-side menu, go to Droplets > Wazuh > Access > Launch Droplet Console. This allows us to connect to the Wazuh server using SSH:

<img width="780" height="439" alt="Wazuh Installation" src="https://github.com/user-attachments/assets/904756bd-1d78-47d3-9c77-29972af217b7" />

**3.2.4 Update and Upgrade the System:**
First, we update and upgrade the system to ensure we have the latest packages and security patches:
```
sudo apt-get update && sudo apt-get upgrade
```
**3.2.5 Install Wazuh:**
We start the Wazuh installation using the official Wazuh installer script:
```
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```
The installation process will begin:

<img width="780" height="439" alt="Wazuh Cmd" src="https://github.com/user-attachments/assets/ef82b7f6-99c2-4904-aabe-5738442b8f4a" />

We take note of the generated password for the "admin" user:
```
User: admin
Password: *******************
```

**3.2.6 Access the Wazuh Web Interface:**
To log in to the Wazuh web interface, we open a web browser and enter the Wazuh server's public IP address with `https://` prefix:

Click "Proceed" and "Continue" to bypass the self-signed SSL certificate warning:

<img width="966" height="844" alt="Wazuh Webpage" src="https://github.com/user-attachments/assets/80351edb-c113-4eff-9048-ea33a00d5fa1" />


Use the generated password with the username "admin" to log in to the Wazuh web interface:

<img width="1698" height="1074" alt="Wazuh login open page" src="https://github.com/user-attachments/assets/0c0f0f0f-7c90-4788-96dd-7a3611a2bbf7" />


Now we have our client machine and Wazuh server up and running. The next step is to install TheHive.

### 3.3 Step 3: Install TheHive

**3.3.1 Create a New Droplet for TheHive:**
We create another Droplet on DigitalOcean with Ubuntu 22.04 for hosting TheHive:

<img width="1920" height="839" alt="the hive" src="https://github.com/user-attachments/assets/b6448a65-fb20-4fa7-8ed4-57cb2a3e7bd4" />


Also, enable the firewall that we set up earlier for the TheHive Droplet.

**3.3.2 Install Dependencies:**
We start by installing the necessary dependencies for TheHive:
```
apt install wget gnupg apt-transport-https git ca-certificates ca-certificates-java curl software-properties-common python3-pip lsb-release
```

<img width="780" height="439" alt="The hive cmd" src="https://github.com/user-attachments/assets/4bb9088e-9361-4174-9861-14f3bcfe3d45" />


**3.3.3 Install Java:**
```
wget -qO- https://apt.corretto.aws/corretto.key | sudo gpg --dearmor -o /usr/share/keyrings/corretto.gpg
echo "deb [signed-by=/usr/share/keyrings/corretto.gpg] https://apt.corretto.aws stable main" | sudo tee -a /etc/apt/sources.list.d/corretto.sources.list
sudo apt update
sudo apt install java-common java-11-amazon-corretto-jdk
echo JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto" | sudo tee -a /etc/environment
export JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto"
```

**3.3.4 Install Cassandra:**
Cassandra is the database used by TheHive for storing data.
```
wget -qO - https://downloads.apache.org/cassandra/KEYS | sudo gpg --dearmor -o /usr/share/keyrings/cassandra-archive.gpg
echo "deb [signed-by=/usr/share/keyrings/cassandra-archive.gpg] https://debian.cassandra.apache.org 40x main" | sudo tee -a /etc/apt/sources.list.d/cassandra.sources.list
sudo apt update
sudo apt install cassandra
```

**3.3.5 Install Elasticsearch:**
Elasticsearch is used by TheHive for indexing and searching data.
```
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
sudo apt-get install apt-transport-https
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list
sudo apt update
sudo apt install elasticsearch
```

**3.3.6 Optional Elasticsearch Configuration:**
Create a `jvm.options` file under `/etc/elasticsearch/jvm.options.d` and add the following configurations to optimize Elasticsearch performance:
```
-Dlog4j2.formatMsgNoLookups=true
-Xms2g
-Xmx2g
```

**3.3.7 Install TheHive:**
```
wget -O- https://archives.strangebee.com/keys/strangebee.gpg | sudo gpg --dearmor -o /usr/share/keyrings/strangebee-archive-keyring.gpg
echo 'deb [signed-by=/usr/share/keyrings/strangebee-archive-keyring.gpg] https://deb.strangebee.com thehive-5.2 main' | sudo tee -a /etc/apt/sources.list.d/strangebee.list
sudo apt-get update
sudo apt-get install -y thehive
```

Default credentials for accessing TheHive on port 9000:
```
Username: admin@thehive.local
Password: secret
```

<img width="780" height="439" alt="elasticsearch the hive install" src="https://github.com/user-attachments/assets/15b6a240-3c6b-480a-b826-cee8da96541a" />


### 3.4 Step 4: Configure TheHive and Wazuh

**3.4.1 Configure Cassandra:**
Cassandra is TheHive's database. We need to configure it by modifying the `cassandra.yaml` file:
```
nano /etc/cassandra/cassandra.yaml
```
This is where we customize the listen address, ports, and cluster name.

<img width="780" height="439" alt="Cassandra xml edit" src="https://github.com/user-attachments/assets/ccef135f-0f9c-4061-8642-c3ae1e49c9ae" />


Set the `listen_address` to TheHive's public IP:

<img width="780" height="439" alt="cassandra edit 2" src="https://github.com/user-attachments/assets/176ecdcf-696b-4bfb-ac5b-487588c788a5" />

Next, configure the RPC address by entering TheHive's public IP.

Lastly, change the seed address under the `seed_provider` section. Enter TheHive's public IP in the `seeds` field:

<img width="780" height="439" alt="Cassandra edit 3" src="https://github.com/user-attachments/assets/e1bbee2a-9550-4d91-ae0f-c9a86c3e47fc" />

Stop the Cassandra service:
```
systemctl stop cassandra.service
```
Remove the old Cassandra data files since we installed TheHive using the package:
```
rm -rf /var/lib/cassandra/*
```
Start the Cassandra service again:
```
systemctl start cassandra.service
```
Check the Cassandra service status to ensure it's running:
```
systemctl status cassandra.service
```

<img width="780" height="439" alt="Cassandra service restart" src="https://github.com/user-attachments/assets/eafb7ffb-c004-4a1d-a153-b6ad6a07e777" />


**3.4.2 Configure Elasticsearch:**
Elasticsearch is used for data indexing in TheHive. We need to configure it by modifying the `elasticsearch.yml` file:
```
nano /etc/elasticsearch/elasticsearch.yml
```

Optionally, change the cluster name.
Uncomment the `node.name` field.
Uncomment the `network.host` field and set the IP to TheHive's public IP.


Optionally, uncomment the `http.port` field (default port is 9200).
Optionally, uncomment the `cluster.initial_master_nodes` field, remove `node-2` if not applicable.

Start and enable the Elasticsearch service:
```
systemctl start elasticsearch
systemctl enable elasticsearch
```

Check the Elasticsearch service status:
```
systemctl status elasticsearch
```

<img width="780" height="439" alt="elastic search running" src="https://github.com/user-attachments/assets/eb55beb7-a949-4a7a-a104-f7be2b056e48" />


**3.4.3 Configure TheHive:**
Before configuring TheHive, ensure the `thehive` user and group have access to the necessary file paths:
```
ls -la /opt/thp
```

<img width="780" height="439" alt="directory change the hive" src="https://github.com/user-attachments/assets/e4e81c31-b527-4c9b-9979-2b722d70b45a" />


If `root` has access to the `thehive` directory, change the ownership:
```
chown -R thehive:thehive /opt/thp
```
This command changes the owner to the `thehive` user and group for the specified directories.

<img width="780" height="439" alt="Directory check the hive" src="https://github.com/user-attachments/assets/2abda619-fb79-4691-a890-839ade3eed2f" />

Now, configure TheHive's configuration file:
```
nano /etc/thehive/application.conf
```

Modify the `database` and `index config` sections.
Change the `hostname` IP to TheHive's public IP.
Set the `cluster.name` to the same value as the Cassandra cluster name ("Test Cluster" in this example).
Change the `index.search.hostname` to TheHive's public IP.
At the bottom, change the `application.baseUrl` to TheHive's public IP.

By default, TheHive has both Cortex (data enrichment and response) and MISP (threat intelligence platform) enabled.

<img width="780" height="439" alt="Hive xml edit" src="https://github.com/user-attachments/assets/49ce171c-1923-4c6f-96a3-73881facd2a2" />
<img width="780" height="439" alt="Hive xml1 edit" src="https://github.com/user-attachments/assets/a0cbbb94-3956-4827-826a-6a18447c2b30" />



Save the file, start, and enable the TheHive service:
```
systemctl start thehive
systemctl enable thehive
```


Important note: If you cannot access TheHive, ensure all three services (Cassandra, Elasticsearch, and TheHive) are running. If any of them are not running, TheHive won't start.

If all services are running, access TheHive from a web browser using TheHive's public IP and port 9000:
```
http://143.198.56.201:9000/login
```

<img width="780" height="410" alt="Hive login web" src="https://github.com/user-attachments/assets/28952607-d728-491b-acf0-8464c013c10f" />


Log in to TheHive using the default credentials:
Username: `admin@thehive.local`
Password: `secret`

<img width="780" height="410" alt="Hive logon web" src="https://github.com/user-attachments/assets/159ca42f-d540-485f-8bd2-1c2b85b41a6b" />


### 3.5 Step 5: Configure Wazuh

**3.5.1 Add a Windows Agent in Wazuh:**
Log in to the Wazuh web interface.
Click on "Add agent" and select "Windows" as the agent's operating system.
Set the server address to the Wazuh server's public IP.

<img width="780" height="412" alt="Wazuh agent create" src="https://github.com/user-attachments/assets/eb876d40-2660-4be2-9c2b-e5026e1bdbc5" />


Copy the installation command provided and execute it in PowerShell on the Windows client machine. The Wazuh agent installation will start.

<img width="770" height="387" alt="running wazuh command powershell" src="https://github.com/user-attachments/assets/aa54ffa7-77e6-410f-8aad-fd8ad247f36f" />


After the installation, start the Wazuh agent service using the `net start wazuhsvc` command or through Windows Services.

<img width="770" height="387" alt="running wazuh command powershell" src="https://github.com/user-attachments/assets/6d9e2b1d-d57d-4247-ad4a-d43b478098ea" />
<img width="805" height="594" alt="Pasted image 20240604002624" src="https://github.com/user-attachments/assets/b46cf524-6a64-4809-8b55-bb20dc8fd07f" />



**3.5.2 Verify the Wazuh Agent:**
Check the Wazuh web interface to confirm the Windows agent is successfully connected.

<img width="780" height="412" alt="Wazuh agent check" src="https://github.com/user-attachments/assets/a467df52-da52-4a60-980d-5626afbb2b2f" />


The Windows agent should be listed with an "Active" status.

<img width="780" height="409" alt="Wazuh security event page" src="https://github.com/user-attachments/assets/55805e71-9f97-4d6f-9e50-1b960dac57fc" />


Now you can start querying events from the Windows agent in Wazuh.

## 4. Generating Telemetry and Custom Alerts

### 4.1 Configure Sysmon Event Forwarding to Wazuh

**4.1.1 Modify Wazuh Agent Configuration:**
On the Windows client machine, navigate to `C:\Program Files (x86)\ossec-agent` and open the `ossec.conf` file with a text editor (e.g., Notepad).

<img width="780" height="439" alt="Ossec edit 1" src="https://github.com/user-attachments/assets/76b124df-821b-4542-a3be-a748118dc56d" />


**4.1.2 Add Sysmon Event Forwarding:**
In the `ossec.conf` file, add a new `<localfile>` section to configure Sysmon event forwarding to Wazuh.
Check the full name of the Sysmon event log in the Windows Event Viewer.

<img width="639" height="183" alt="Pasted image 20240604150516" src="https://github.com/user-attachments/assets/184c50de-b3ea-4a82-b05f-3af264d15ac3" />


Add the following configuration to the `ossec.conf` file:

<img width="502" height="198" alt="Pasted image 20240604150556" src="https://github.com/user-attachments/assets/1ff19a5a-47fe-41d9-849b-f1fb8253ae38" />


Optional: You can also configure forwarding for other event logs like PowerShell, Application, Security, and System. In this lab, we will remove the Application, Security, and System sections to focus on Sysmon events.

**4.1.3 Save the Configuration File:**
Since modifying the `ossec.conf` file requires administrator privileges, open a new Notepad instance with administrator rights and save the changes to the file.

**4.1.4 Restart the Wazuh Agent Service:**
Restart the Wazuh agent service to apply the configuration changes.

<img width="804" height="594" alt="Pasted image 20240604151539" src="https://github.com/user-attachments/assets/7df9c321-c659-4765-b6fe-e50b67603c5e" />

Note: Whenever you modify the Wazuh agent configuration, you need to restart the service either through PowerShell or Windows Services.

**4.1.5 Verify Sysmon Event Forwarding:**
In the Wazuh web interface, go to the "Events" section and search for Sysmon events to confirm they are being received.

<img width="780" height="412" alt="Sysmon Wazuh check" src="https://github.com/user-attachments/assets/1ed7ea3e-5ef5-4825-981d-23601083db3a" />

### 4.2 Generate Mimikatz Telemetry

**4.2.1 Download Mimikatz:**
On the Windows client machine, download Mimikatz, a tool commonly used by attackers and red teamers to extract credentials from memory.
To download Mimikatz, you may need to temporarily disable Windows Defender or exclude the download directory from scanning.

<img width="1917" height="829" alt="Exclusions" src="https://github.com/user-attachments/assets/7dc52a02-53d7-499e-a2b1-f3452e3b525c" />


**4.2.2 Execute Mimikatz:**
Open PowerShell, navigate to the directory where Mimikatz is downloaded, and execute it.

<img width="780" height="439" alt="Mimikatz power shell" src="https://github.com/user-attachments/assets/22b8a1b9-d811-4453-a68d-95566f00e85f" />


**4.2.3 Configure Wazuh to Log All Events:**
By default, Wazuh only logs events that trigger a rule or alert. To log all events, modify the Wazuh manager's `ossec.conf` file.
Connect to the Wazuh server via SSH and open `/var/ossec/etc/ossec.conf`.
Create a backup of the original configuration file:
```
cp /var/ossec/etc/ossec.conf ~/ossec-backup.conf
```

<img width="828" height="520" alt="Pasted image 20240604154130" src="https://github.com/user-attachments/assets/bb7cd1cd-5c96-4e92-a870-31b750431c97" />


Change the `<logall>` and `<logall_json>` options under the `<ossec_config>` section from "no" to "yes".
Restart the Wazuh manager service:
```
systemctl restart wazuh-manager.service
```

This configuration forces Wazuh to archive all logs in the `/var/ossec/logs/archives/` directory.

**4.2.4 Configure Filebeat:**
To enable Wazuh to ingest the archived logs, modify the Filebeat configuration:
```
nano /etc/filebeat/filebeat.yml
```

<img width="780" height="439" alt="Filebeat XML" src="https://github.com/user-attachments/assets/1e3ce3f9-7bd7-4dbd-86b5-68b46b727c67" />


Change the `enabled: false` to `true` for the "archives" input and restart the Filebeat service.

**4.2.5 Create a New Index in Wazuh:**
After updating Filebeat and the Ossec configuration, create a new index in the Wazuh web interface to search the archived logs.
From the left-side menu, go to "Stack Management" > "Index Management".

<img width="1457" height="551" alt="Pasted image 20240604154910" src="https://github.com/user-attachments/assets/a88c2866-999f-4080-a67f-3453602c8d1a" />


Create a new index named `wazuh-archives-*` to cover all archived logs.

<img width="773" height="408" alt="Wazuh indexes 1" src="https://github.com/user-attachments/assets/da6b2b40-547f-47ba-94eb-472d43027571" />


On the next page, select "timestamp" as the time field and create the index.

<img width="780" height="411" alt="Wazuh indixes 2" src="https://github.com/user-attachments/assets/f784ef04-b7fd-4d23-893a-a43847d6076a" />

<img width="780" height="409" alt="Wazuh indixes 3" src="https://github.com/user-attachments/assets/302b7635-07d1-4023-bb85-ebeed7904a3a" />



Go to the "Discover" section from the left-side menu and select the newly created index.
<img width="780" height="412" alt="Wazuh archives dashboard" src="https://github.com/user-attachments/assets/0710c33a-f62f-45f7-bbe2-98e27aa1b96f" />


**4.2.6 Troubleshoot Mimikatz Logs:**
To troubleshoot if Mimikatz logs are being archived, use `cat` and `grep` on the archive logs in the Wazuh manager CLI:
```
cat /var/ossec/logs/archives/archives.log | grep -i mimikatz

<img width="780" height="439" alt="mimikatz" src="https://github.com/user-attachments/assets/21af3efe-6469-4a65-839e-de767a42bd86" />


### 4.3 Create a Custom Mimikatz Alert

**4.3.1 Analyze Mimikatz Logs:**
Examine the Mimikatz logs and identify a suitable field for crafting an alert. In this example, we will use the `originalfilename` field.

<img width="780" height="439" alt="mimikatz dashboard" src="https://github.com/user-attachments/assets/116acdff-7cc9-4779-8a4f-4a514085cb3c" />

<img width="780" height="439" alt="mimikatz dashboard 2" src="https://github.com/user-attachments/assets/cc16f13c-cc2c-4539-90fe-c8084a0280de" />

<img width="780" height="439" alt="Mimikatz dashboard 3" src="https://github.com/user-attachments/assets/05316309-85dd-4d40-9d50-70b418b7cb4d" />



Using the `originalfilename` field ensures the alert will trigger even if an attacker changes the Mimikatz executable name.

**4.3.2 Create a Custom Rule:**
You can create a custom rule either from the CLI or the Wazuh web interface.

<img width="780" height="386" alt="wazuh rules" src="https://github.com/user-attachments/assets/cc8d346e-9172-4266-acbe-26ddeed9c773" />

In the web interface, click on the "Manage rule files" button. Filter the rules by name (e.g., "sysmon") and view the rule details by clicking the eye icon.

<img width="1164" height="1192" alt="Pasted image 20240604165717" src="https://github.com/user-attachments/assets/ed335296-7a25-454d-9723-bdbac3a60585" />

These are Sysmon-specific rules built into Wazuh for event ID 1. Copy one of these rules as a reference and modify it to create a custom Mimikatz detection rule.

Example custom rule:
```xml
<rule id="100002" level="15">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.originalFileName" type="pcre2">(?i)\\mimikatz\.exe</field>
  <description>Mimikatz Usage Detected</description>
  <mitre>
    <id>T1003</id>
  </mitre>
</rule>
```

Go to the "Custom rules" button and edit the "local_rules.xml" file. Add the custom Mimikatz detection rule.

<img width="780" height="405" alt="wazuh rules 2" src="https://github.com/user-attachments/assets/a9760750-a2c5-424d-9a71-b5aa0a44bbc3" />

Save the file and restart the Wazuh manager service.

**4.3.3 Test the Custom Rule:**
To test the custom rule, rename the Mimikatz executable on the Windows client machine to something different.

Execute the renamed Mimikatz.

<img width="780" height="439" alt="Mimikatz powershell 1" src="https://github.com/user-attachments/assets/345d785f-4203-4bf6-84d2-2b5e1f53233d" />


Verify that the custom rule triggers an alert in Wazuh, even with the renamed Mimikatz executable.

<img width="779" height="359" alt="Mimikatz wazuh dashboard" src="https://github.com/user-attachments/assets/0fe32c75-cf02-4822-b179-7b134a04a7ee" />

## 5. Automation with Shuffle and TheHive

### 5.1 Set Up Shuffle

**5.1.1 Create a Shuffle Account:**
Go to the Shuffle website (shuffler.io) and create an account.

<img width="778" height="386" alt="Shuffle" src="https://github.com/user-attachments/assets/3615fb11-6c4a-409b-a73e-f034b8c2e8b3" />


**5.1.2 Create a New Workflow:**
Click on "New Workflow" and create a workflow. You can select any random use case for demonstration purposes.

<img width="1212" height="1038" alt="Pasted image 20240604213428" src="https://github.com/user-attachments/assets/68a9ede7-0ffc-4551-b7e4-4654de09eeb3" />


**5.1.3 Add a Webhook Trigger:**
On the workflow page, click on "Triggers" at the bottom left. Drag a "Webhook" trigger and connect it to the "Change Me" node.
Set a name for the webhook and copy the Webhook URI from the right side. This URI will be added to the Ossec configuration on the Wazuh manager.

<img width="773" height="335" alt="Shuffle flow" src="https://github.com/user-attachments/assets/40f93062-edae-44c8-b7c1-52b3b6da6320" />


**5.1.4 Configure the "Change Me" Node:**
Click on the "Change Me" node and set it to "Repeat back to me" mode. For call options, select "Execution argument". Save the workflow.



**5.1.5 Configure Wazuh to Connect to Shuffle:**
On the Wazuh manager CLI, modify the `ossec.conf` file to add an integration for Shuffle:
```
nano /var/ossec/etc/ossec.conf
```

Add the following integration configuration:
```xml
<integration>
  <name>shuffle</name>
  <hook_url>https://shuffler.io/api/v1/hooks/webhook_0af8a049-f2cb-420b-af58-5ebc3c40c7df</hook_url>
  <level>3</level>
  <alert_format>json</alert_format>
</integration>
```

Replace the `<level>` tag with `<rule_id>100002</rule_id>` to send alerts based on the custom Mimikatz rule ID.

Restart the Wazuh manager service:
```
systemctl restart wazuh-manager.service
```
<img width="780" height="439" alt="Shuffle wazuh restart" src="https://github.com/user-attachments/assets/e8fa0c96-aa23-4e09-8245-8981184f8414" />


**5.1.6 Test the Shuffle Integration:**
Regenerate the Mimikatz telemetry on the Windows client machine.
In Shuffle, click on the webhook trigger ("Wazuh-Alerts") and click "Start".

<img width="830" height="613" alt="Pasted image 20240604230243" src="https://github.com/user-attachments/assets/b790d25d-409f-4ae8-b07e-871d4f83ca2e" />

Verify that the alert is received in Shuffle.

### 5.2 Build a Mimikatz Workflow

**Workflow Steps:**
1. Mimikatz alert sent to Shuffle
2. Shuffle receives Mimikatz alert / extract SHA256 hash from file
3. Check reputation score with VirusTotal
4. Send details to TheHive to create an alert
5. Send an email to the SOC analyst to begin the investigation

**5.2.1 Extract SHA256 Hash:**
Observe that the return values for the hashes are appended by their hash type (e.g., `sha1=hashvalue`).
To automate the workflow, parse out the hash value itself. Sending the entire value, including `sha1=`, to VirusTotal will result in an invalid query.

Click on the "Change Me" node and select "Regex capture group" instead of "Repeat back to me".
In the "Input data", select the "hashes" option.
In the "Regex" tab, enter the regex pattern to parse the SHA256 hash value: `SHA256=([0-9A-Fa-f]{64})`.
Save the workflow.

<img width="776" height="366" alt="regex virus total" src="https://github.com/user-attachments/assets/983e58e4-0962-40da-af44-801cec9c0db3" />


Click on the "Show execution" button (running man icon) to verify that the hash value is extracted correctly.

<img width="777" height="358" alt="Shuffle  succes" src="https://github.com/user-attachments/assets/4b8888b4-196c-459c-a83e-0f96ff317c8c" />


**5.2.2 Integrate VirusTotal:**
Create a VirusTotal account to access the API.

<img width="780" height="346" alt="Virus total API" src="https://github.com/user-attachments/assets/26e422fe-8b6b-4637-a3eb-d9f8eff267d3" />


Copy the API key and return to Shuffle.
In Shuffle, click on the "Apps" tab and search for "VirusTotal". Drag the "VirusTotal" app to the workflow, and it will automatically connect.

<img width="1397" height="1067" alt="Pasted image 20240605000230" src="https://github.com/user-attachments/assets/fa1d425f-9883-4541-b3ef-1800a437d394" />

Enter the API key on the right side or click "Authenticate VirusTotal v3" to authenticate.

<img width="780" height="412" alt="Virus total API Key" src="https://github.com/user-attachments/assets/f30e5a8c-3e8f-40be-93c2-668844498f7f" />

Change the "ID" field to the "SHA256Regex" value created earlier.

<img width="780" height="392" alt="virus total results" src="https://github.com/user-attachments/assets/9df7ac46-ad5e-4311-97b4-24fab688f6f8" />


Save the workflow and rerun it.

<img width="780" height="406" alt="virus total shuffle success" src="https://github.com/user-attachments/assets/ff75ffee-d988-47b2-996c-659d5e77a63b" />


Expand the results to view the VirusTotal scan details, including the number of detections.

<img width="788" height="606" alt="Pasted image 20240605002209" src="https://github.com/user-attachments/assets/f5420603-675f-4931-9887-8125f13fe00d" />


**5.2.3 Integrate TheHive:**
In Shuffle, search for "TheHive" in the "Apps" and drag it into the workflow.
TheHive can be connected using the IP address and port number (9000) of the TheHive instance created on DigitalOcean.

<img width="1920" height="839" alt="image" src="https://github.com/user-attachments/assets/4847f071-bb13-425d-a43b-ac4e2adc6b89" />


Log in to TheHive using the default credentials:
Username: `admin@thehive.local`
Password: `secret`

**5.2.4 Configure TheHive:**
Create a new organization and user for the organization in TheHive.

<img width="1391" height="458" alt="Pasted image 20240605113123" src="https://github.com/user-attachments/assets/664c2bdd-b25c-4ca6-b14e-6610481297ba" />


Add new users with different profiles as needed.

<img width="780" height="439" alt="Adding users hive" src="https://github.com/user-attachments/assets/2fa2b81a-9b4e-497a-8a4b-d9a0377ab114" />


Set new passwords for the users.
For the SOAR user created for Shuffle integration, generate an API key.

<img width="780" height="411" alt="Users added hive" src="https://github.com/user-attachments/assets/32871191-462a-48de-be86-9776804abcd5" />


Create an API key and store it securely. This key will be used to authenticate Shuffle.

<img width="779" height="391" alt="SOAR api key" src="https://github.com/user-attachments/assets/f897134f-d04a-447c-a1e1-f7de8d76b763" />

Log out from the admin account and log in with one of the user accounts.


**5.2.5 Configure Shuffle to Work with TheHive:**
In Shuffle, click on the orange "Authenticate TheHive" button and enter the API key created earlier.
For the URL, enter the public IP address of TheHive along with the port number.

<img width="780" height="439" alt="API Key shuffle from SOAR" src="https://github.com/user-attachments/assets/138af3f0-48d9-496b-961a-024e6d97ef73" />


Under "Find actions", click on "TheHive" and select "Create alerts".
Set the JSON payload for TheHive to receive the alerts. Here's an example payload for the Mimikatz scenario:

```json
{
  "description": "Mimikatz Detected on host: DESKTOP-HS8N3J7",
  "externallink": "",
  "flag": false,
  "pap": 2,
  "severity": "2",
  "source": "Wazuh",
  "sourceRef": "Rule:100002",
  "status": "New",
  "summary": "Details about the Mimikatz detection",
  "tags": [
    "T1003"
  ],
  "title": "Mimikatz Detection Alert",
  "tlp": 2,
  "type": "Internal"
}
```

Expand the "Body" section to set the payload.

<img width="639" height="789" alt="Pasted image 20240605141313" src="https://github.com/user-attachments/assets/f4f3bf1c-1fbb-4c54-8a0f-5a431675668f" />

Set the payload on the left side and test the output on the right side.

<img width="779" height="345" alt="Shuffle code to integrate with  hive for alert" src="https://github.com/user-attachments/assets/3e225b7f-a250-4362-8312-41d65b8977cc" />

Save the workflow and rerun it. An alert should appear in the TheHive dashboard.

<img width="780" height="439" alt="Hive alert web opage" src="https://github.com/user-attachments/assets/db9cbab1-399c-4c46-b592-aee9ef999ef4" />


Note: If the alert doesn't appear, ensure that the firewall for TheHive in your cloud provider allows inbound traffic on port 9000 from any source.

Click on the alert to view the details.

<img width="780" height="439" alt="Hive web page details" src="https://github.com/user-attachments/assets/414e759b-4dd7-4bde-8a42-c2e6b2dc1168" />

**5.2.6 Send Email Notification:**
In Shuffle, find "Email" in the "Apps" and connect VirusTotal to the email node.

Configure the email settings, including the recipient, subject, and body, to send the alert with relevant event information.

<img width="774" height="361" alt="Shuffle email" src="https://github.com/user-attachments/assets/0fc70c1b-c0d3-4bfb-b228-0e69dd12ab46" />

Save the workflow and rerun it.

<img width="487" height="651" alt="Pasted image 20240605170809" src="https://github.com/user-attachments/assets/0ba6153e-cc4e-4bcf-84df-7c0b840a8adc" />


Verify that the email is received with the expected alert details.

<img width="362" height="237" alt="Shuffle email sent" src="https://github.com/user-attachments/assets/b1d56522-67cb-4d13-965d-d33f9a6e68f7" />


## 6. Conclusion

I have successfully set up and configured the SOC Automation Lab, integrating Wazuh, TheHive, and Shuffle for automated event monitoring, alerting, and incident response. This foundation provides a solid starting point for further customization and expansion of automation workflows to meet our specific SOC requirements.
The key steps and achievements of this lab include:

1. Installing and configuring a Windows 10 client with Sysmon for detailed event generation.
2. Setting up Wazuh as the central event management and alerting platform.
3. Installing and configuring TheHive for case management and coordinated response actions.
4. Generating Mimikatz telemetry and creating custom alerts in Wazuh.
5. Integrating Shuffle as the SOAR platform for workflow automation.
6. Building an automated workflow to extract file hashes, check reputation scores with VirusTotal, create alerts in TheHive, and notify SOC analysts via email.

With this lab, I have gained hands-on experience in implementing an automated SOC workflow using powerful open-source tools. We can now leverage this knowledge to enhance your organization's security operations, improve incident response times, and streamline SOC processes.

