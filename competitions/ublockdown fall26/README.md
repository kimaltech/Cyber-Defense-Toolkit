# Incident Response & Service Remediation: Securing Ubuntu 2

## Overview
During a collegiate cyber defense competition, our blue team experienced scoring outages on our Linux infrastructure—specifically targeting the `Ubuntu2: SSH` service. This report covers the technical remediation used to diagnose scoring engine failures, eradicate persistence mechanisms, block active unauthorized intrusions, and restore critical services while hardening host configurations against red team attacks.

---
## Initial Hardening Procedures
The first two things I did was reset the password and enable the firewall

```bash
# I changed the password using the command:
passwd

# Then I enabled the firewall and checked its status
sudo ufw enable
sudo ufw status
sudo systemctl start firewalld
sudo systemctl enable firewalld
sudo firewall-cmd --state
```
I then deleted unknown users from the machine after viewing the large list of users:

```bash
sudo deluser <username>
```

---

## First SSH Outage & Root-Cause Analysis
The competition scoreboard initially flagged `Ubuntu2: SSH` as failed. I ran these commands to troubleshoot the issue:

```bash
# I checked and started the service
sudo systemctl status ssh
sudo systemctl restart ssh
sudo systemctl enable ssh

# Then I verified if sshd was actually listening to port 22
sudo ss -tulpn | grep :22

# It was listening so I allowed traffic through firewall
sudo ufw allow 22/tcp
sudo ufw reload

# Then I checked the ssh logs using:
sudo journalctl -u ssh -f
```

---
The authentication logs showed frequent connection attempts originating from 192.168.10.8 attempting to authenticate as user "Blake":
* sshd[1937516]: Invalid user Blake from 192.168.10.8 port 46402
* sshd[1937516]: pam_unix(sshd:auth): check pass; user unknown
* sshd[1937516]: Failed password for invalid user Blake from 192.168.10.8 port 46402

# 1. Initial Mistake & Containment
Operating under the assumption that "Blake" was an active Red Team credential attack from 192.168.10.8, I deleted the user along with otehr unknown users.

This stopped the brute-force alerts, but the scoreboard immediately flagged SSH as offline with critical round failures.

# 2. Re-Identifying Scoring Criteria & Restoring Blake
Navigating to the scoring engine dashboard (engine.ubnetdef.org/details) revealed the actual check parameters:

Service: Ubuntu2: SSH

Target Command: whoami

Expected Output: Blake

Target User: Blake

Password: Changeme2026!

Engine Error: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password], no supported methods remain

The account was not an adversary—it was the automated scoring probe.

# Restoring Scoring Engine Access

The user was recreated with a proper shell and the expected competition credentials:

```bash
# Recreate scoring account
sudo useradd -m -s /bin/bash Blake
echo 'Blake:Changeme2026!' | sudo chpasswd
sudo passwd -u Blake

# Force priority SSH password authentication override
sudo bash -c 'cat <<EOF> /etc/ssh/sshd_config.d/99-scoring.conf
PasswordAuthentication yes
KbdInteractiveAuthentication yes
PubkeyAuthentication yes
PermitRootLogin no
EOF'
sudo systemctl restart ssh

# Verify Immediately
ssh -o PreferredAuthentications=password Blake@localhost whoami
```

## 3. Account Hardening & Least Privelege Configuration
Becase the scoring bot shared a known default password (Changeme2026!) eith whoami priveleges, the account posed an escalation vector for adversaries. The account was locked down to prevent privelege abuse:

```bash
# Strip administrative privileges
sudo deluser Blake sudo 2>/dev/null
sudo deluser Blake admin 2>/dev/null

# Lock out scheduled execution
echo "Blake" | sudo tee -a /etc/cron.deny /etc/at.deny > /dev/null

# Make home directory read-only to Blake to block unauthorized SSH authorized_keys persistence
sudo chown root:root /home/Blake
sudo chmod 755 /home/Blake
sudo rm -rf /home/Blake/.ssh
```

## 4. Defending Ports & Filtering Traffic with IPTables
To ensure Red Team could not interact with port 22 or launch network-level brute-force attacks, iptables was configured to restrict traffic strictly to the verified scoring subnet (1922.168.10.0/24) and loopback:

```bash
# 1. Allow ICMP for Ubuntu2: PING checks
sudo iptables -I INPUT 1 -p icmp --icmp-type echo-request -j ACCEPT

# 2. Allow scoring engine subnet strictly to port 22
sudo iptables -I INPUT 2 -p tcp -s 192.168.10.0/24 --dport 22 -j ACCEPT

# 3. Allow internal localhost checks
sudo iptables -I INPUT 3 -p tcp -s 127.0.0.1 --dport 22 -j ACCEPT

# 4. Drop all other external SSH ingress
sudo iptables -A INPUT -p tcp --dport 22 -j DROP
```

# Enforcing Rule Persistance
To ensure rules survived reboots or network resets, iptables-persistent was installed and saved:

```bash
sudo apt-get install -y iptables-persistent
sudo netfilter-persistent save
```
Subsequent inspection verified packet flow matching the ~25-second scoring intervals

## 5. Desktop Pop-Up Remediation & Backdoor Neutralization
During the defense phase, a distraction UI labeled "EMPLOYMENT / JOB APPLICATION" spawned repeatedly across the graphical session.

# Process Hunting
Inspecting running processes uncovered a backdoor listener bound to all network interfaces on port 8765:

```bash
ps aux | grep -iE 'firefox|chrome|chromium|evince|xdg-open|python|node'
```

Process table excerpt:

```plaintext
sysadmin 4088705 0.0 0.1 107988 6836 ? Ss Oct21 0:52 /usr/bin/python3 /usr/local/bin/notify listen --host 0.0.0.0 --port 8765
```

# Remediation & Elimination

```bash
# 1. Terminated rogue backdoor listner:
sudo kill -9 4088705
sudo rm -f /usr/local/bin/notify

# 2. Killed active GUI pop-up windows
xkill

# 3. Swept staging locations for persistence:
find /home/sysadmin /tmp /opt -iname "*employment*" -o -iname "*job*" -delete 2>/dev/null
```

## Key Takeaways
* **Validate Engine Traffic Before Deprovisioning:** Verifying traffic patterns and scoring engine documentation before deleting unrecognizing accounts or disabling authentication mechanisms
* **Implement Network Whitelisting Early:** Locking port access directly to known engine subnets via iptables mitigates external brute-force vectors while keeping uptime green.
* **Constrain Engine Credentials:** Service accounts required by automated scoring bots should have restricted sudo, no cron privieges, and read-only home directories to avoid weaponization.
