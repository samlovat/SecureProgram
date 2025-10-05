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
- **Exploitation:** Inject SQL commands like `admin' OR '1'='1' --`

### **2. Weak Password Hashing (MD5)**
- **File:** `cli_crypto.py` - `hash_password()` and `verify_password()` functions
- **Type:** Cryptographic Security / Password Security
- **Description:** Uses broken MD5 hashing instead of secure scrypt
- **Impact:** Password cracking, account takeover
- **Exploitation:** Brute force attacks, rainbow table lookups

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

- `timing_attack_example.py` - Demonstrates username enumeration
- `sql_injection_exploit.py` - Shows database extraction techniques  
- `md5_cracking_exploit.py` - Demonstrates password cracking
- `complete_attack_chain.py` - Chains all vulnerabilities together

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
