# ⚠️ ETHICAL HACKING VULNERABILITIES - INTENTIONALLY VULNERABLE CODE ⚠️

## WARNING
**THIS CODE CONTAINS INTENTIONAL SECURITY VULNERABILITIES FOR EDUCATIONAL PURPOSES ONLY**

**DO NOT USE THIS CODE IN PRODUCTION ENVIRONMENTS!**

This repository has been modified to include 3 intentional security vulnerabilities for ethical hacking education and competition purposes.

---

## 🎯 **Vulnerabilities Included**

### **1. SQL Injection Vulnerability**
- **File:** `directory.py` - `get_user()` function
- **Type:** Input Validation / Database Security
- **Description:** User input is directly concatenated into SQL queries without sanitization
- **Impact:** Database compromise, data extraction, authentication bypass
- **Exploitation:** Boolean-based blind injection using error message differences
- **Success Rate:** **100% - All 7 user password hashes successfully extracted**

### **2. Weak Password Hashing (MD5)**
- **File:** `cli_crypto.py` - `hash_password()` and `verify_password()` functions
- **Type:** Cryptographic Security / Password Security
- **Description:** Uses broken MD5 hashing instead of secure scrypt **AND ignores salt completely**
- **Impact:** Password cracking, account takeover, rainbow table attacks
- **Exploitation:** Extract hashes via SQL injection, crack with MD5 brute force (billions/second)
- **Critical Flaw:** `hashlib.md5(password.encode("utf-8"))` - salt parameter completely ignored!

### **3. Timing Attack Vulnerability**
- **File:** `server.py` - `USER_LOGIN` handler
- **Type:** Information Disclosure / Side-Channel Attack
- **Description:** Different response times reveal valid vs invalid usernames
- **Impact:** Username enumeration, reconnaissance
- **Exploitation:** Measure response times to enumerate valid accounts

---

## 🔍 **How to Find the Vulnerabilities**

### **Code Analysis**
Look for these specific patterns in the code:

1. **SQL Injection:** Search for string concatenation in SQL queries
   ```python
   query = f"SELECT ... WHERE user_id='{user_id}'"  # VULNERABLE!
   ```

2. **MD5 Hashing:** Look for MD5 usage instead of scrypt
   ```python
   hashlib.md5(password.encode("utf-8")).digest()  # VULNERABLE!
   ```

3. **Timing Attack:** Look for artificial delays in error handling
   ```python
   time.sleep(0.1)  # VULNERABLE!
   ```

### **Exploitation Scripts**
Use the provided exploitation scripts to test the vulnerabilities:

**Working Exploits:**
- `timing_attack_example.py` - Demonstrates username enumeration
- `blind_sql_injection.py` - **Working** blind SQL injection using boolean-based technique
- `extract_all_hashes.py` - **Complete** password hash extraction from all users
- `crack_all_hashes.py` - **Successful** MD5 password cracking (6/7 passwords cracked)

**Educational Examples:**
- `sql_injection_exploit.py` - Shows UNION-based SQL injection theory (limited by app logic)
- `complete_attack_chain.py` - Chains all vulnerabilities together

---

## 🎯 **Successful Exploitation Results**

### **Complete Attack Chain Executed:**
1. **Timing Attack** → Identified valid usernames: `admin`, `alice`
2. **SQL Injection** → Extracted all 7 user password hashes via blind boolean-based injection
3. **MD5 Cracking** → Successfully cracked 6/7 passwords in 0.001 seconds

### **Compromised Accounts:**
```
testuser1 : password
testuser2 : admin  
testuser3 : 123456
testuser4 : alice
testuser5 : qwerty
admin     : test
alice     : [password not in wordlist]
```

### **Attack Effectiveness:**
- **SQL Injection Success Rate:** 100% (7/7 hashes extracted)
- **Password Cracking Success Rate:** 85.7% (6/7 passwords cracked)
- **Total Time:** < 1 second for complete database compromise
- **Security Breach:** Complete - Multiple user accounts compromised including admin

---

## 🛡️ **Secure Fixes**

### **1. SQL Injection Fix**
```python
# SECURE: Use parameterized queries
row = c.execute("SELECT ... WHERE user_id=?", (user_id,)).fetchone()
```

### **2. Password Hashing Fix**
```python
# SECURE: Use scrypt for password hashing
k = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(password.encode("utf-8"))
```

### **3. Timing Attack Fix**
```python
# SECURE: Always perform same operations regardless of user validity
# - Always hash the password (even for invalid users)
# - Use constant-time string comparison
# - Add random delays to mask timing differences
```

---

## 🎓 **Educational Purpose**

This code is designed for:
- Ethical hacking education
- Security awareness training
- Penetration testing practice
- Secure coding lessons

**Remember:** These vulnerabilities are intentionally introduced for learning purposes. Always follow secure coding practices in real applications!

---

## 📋 **Assignment Requirements**

This submission includes:
- ✅ 3 different types of vulnerabilities
- ✅ Clear labeling of vulnerable code sections
- ✅ Detailed documentation of each vulnerability
- ✅ Exploitation examples and scripts
- ✅ Secure fixes and explanations

**Vulnerability Types:**
1. **SQL Injection** (Input Validation flaw)
2. **Weak Password Hashing** (Cryptographic flaw)  
3. **Timing Attack** (Information Disclosure flaw)
