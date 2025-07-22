# IMAP/POP3 Service Enumeration Writeup

## Overview

Given a target server I was tasked with the enumeration of IMAP and POP3 services.

## Initial Reconnaissance

### Nmap Scan

First, I performed a targeted Nmap scan on the mail service ports:

```bash
[★]$ sudo nmap  -p110,143,993,995 -sC -sV TARGET_IP
```

#### Key Information Discovered:

- Common Name (FQDN): `dev.inlanefreight.htb`
- Organization: `InlaneFreight Ltd`

### IMAP Service Enumeration Flag

I connected to the secure IMAP service using curl and the credentials I was given:

```bash
[★]$ curl -k 'imaps://TARGET_IP' --user robin:robin -v
*   Trying TARGET_IP:993...
* Connected to TARGET_IP (TARGET_IP) port 993 (#0)
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.3 (IN), TLS handshake, Encrypted Extensions (8):
--- SNIP ---
* TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
* old SSL session ID is stale, removing
< * OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ AUTH=PLAIN] HTB{REDACTED}
> A001 CAPABILITY
--- SNIP ---
```

### POP3 Server Version

Connected to POP3 service using OpenSSL: 

```bash
[★]$ openssl s_client -connect TARGET_IP:pop3s
--- AT THE END OF THE TEXT ---
    Start Time: 1753177511
    Timeout   : 7200 (sec)
    Verify return code: 18 (self-signed certificate)
    Extended master secret: no
    Max Early Data: 0
---
read R BLOCK
+OK InFreight POP3 v9.188
--- SNIP ---
```

### Finding Admin Email Address

Using this command:

```bash
[★]$ openssl s_client -connect TARGET_IP:imaps
--- SNIP ---
E LITERAL+ AUTH=PLAIN] HTB{REDACTED}
A1 LOGIN robin robin
A1 OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE SORT SORT=DISPLAY THREAD=REFERENCES THREAD=REFS THREAD=ORDEREDSUBJECT MULTIAPPEND URL-PARTIAL CATENATE UNSELECT CHILDREN NAMESPACE UIDPLUS LIST-EXTENDED I18NLEVEL=1 CONDSTORE QRESYNC ESEARCH ESORT SEARCHRES WITHIN CONTEXT=SEARCH LIST-STATUS BINARY MOVE SNIPPET=FUZZY PREVIEW=FUZZY LITERAL+ NOTIFY SPECIAL-USE] Logged in
A1 LIST "" *
* LIST (\Noselect \HasChildren) "." DEV
* LIST (\Noselect \HasChildren) "." DEV.DEPARTMENT
* LIST (\HasNoChildren) "." DEV.DEPARTMENT.INT
* LIST (\HasNoChildren) "." INBOX
--- SNIP ---
A1 SELECT DEV.DEPARTMENT.INT
* OK [CLOSED] Previous mailbox closed.
* FLAGS (\Answered \Flagged \Deleted \Seen \Draft)
* OK [PERMANENTFLAGS (\Answered \Flagged \Deleted \Seen \Draft \*)] Flags permitted.
* 1 EXISTS
* 0 RECENT
* OK [UIDVALIDITY 1636414279] UIDs valid
* OK [UIDNEXT 2] Predicted next UID
A1 OK [READ-WRITE] Select completed (0.006 + 0.000 + 0.005 secs).
--- SNIP (INBOX WAS EMPTY) ---
A2 SELECT "DEV.DEPARTMENT.INT"
* OK [CLOSED] Previous mailbox closed.
* FLAGS (\Answered \Flagged \Deleted \Seen \Draft)
* OK [PERMANENTFLAGS (\Answered \Flagged \Deleted \Seen \Draft \*)] Flags permitted.
* 1 EXISTS
* 0 RECENT
* OK [UIDVALIDITY 1636414279] UIDs valid
* OK [UIDNEXT 2] Predicted next UID
A2 OK [READ-WRITE] Select completed (0.001 + 0.000 secs).
A3 FETCH 1:* (BODY[TEXT])
* 1 FETCH (BODY[TEXT] {34}
HTB{REDACTED}
)
A3 OK Fetch completed (0.011 + 0.000 + 0.010 secs).
--- SNIP ---
A10 SEARCH ALL
* SEARCH 1
A10 OK Search completed (0.001 + 0.000 secs).
A11 FETCH 1:* (BODY[HEADER.FIELDS (FROM TO CC BCC SUBJECT)])
* 1 FETCH (BODY[HEADER.FIELDS (FROM TO CC BCC SUBJECT)] {94}
Subject: Flag
To: Robin <robin@inlanefreight.htb>
From: CTO <ADMIN MAIL REDACTED>

)
A11 OK Fetch completed (0.001 + 0.000 secs).
```
