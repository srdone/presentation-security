#Points to research:

- How to mitigate against:
    - SQL Injection
    - Cross Site Request Forgery
    - Cross Site Scripting
    - Clickjacking
- Authentication
    - account lockout, password history/expiration, etc.
    - Multi-factor authentication
    - What is the correct way of storing passwords?
    - Why should passwords be salted?
- Input validation
- PII/PHI (e.g. masking certain data in the UI)
- What is OWASP?
- How it relates to Javascript/.NET


#Authentication

##Multi-factor authentication

Security Now #90 - https://www.grc.com/sn/sn-090.htm

Something you know, something you have, and something you are
e.g. - password, token generator, and fingerprint

Many systems (e.g. - google) offer two-factor authentication systems: password and a code you get from a phone call, for example

Advantages:
	- If someone gets one, they still can't get in (e.g. if password is compromised)

Disadvantages:
	- More difficult for the user to keep track of everything
	- Takes longer to log in

##Account lockout, password history/expiration, etc

Advantages:
	- Lockout prevents hackers from trying all the passwords they want until one works
	- Requiring passwords to expire makes it less likely that a password will be compromised
		- Out in the wild for less time
		- Makes it less likely the password will be reused elsewhere

Disadvantages:
	- It can be difficult to remember passwords that change frequently
		- Users might write them down or store them in ways that others can find them

##Password Storage

https://crackstation.net/hashing-security.htm

###Hashing Algorithms
	- turn data into a fixed length string that cannot be reversed
	- hash is completely different even with a small change to the input
	- simple hashing is not sufficient (tools exist that can give you the original value very quickly - "rainbow tables")
		- https://en.wikipedia.org/wiki/Rainbow_table
	- Can have hashing collisions (two strings that when hashed result in the same hash) - rare and difficult to find
	- Commonly used hashing algorithms: SHA256, SHA512, RipeMD, WHIRLPOOL

###Proper workflow
	- User creates account
	- Password is hashed and stored in the database (never written to the hard drive)
	- When user logs in, the hash of the password they entered is compared against the hash stored in the database
	- If hashes match, user is granted access. Otherwise told they entered invalid credentials (not just that the password was wrong)
		- Prevents hackers from figuring out what all the usernames are without knowing passwords
	- Repeat 2nd and 3rd steps each time login is attempted

###Cracking Hashes
	- Dictionary and brute force
		- leet speak equivalents
		- brute force always eventually finds the password
	- Lookup tables
	- Reverse lookup table
		- searching many hashes at once for a result
	- Rainbow tables
	- Tables (above 3) only work when all passwords are hashed in the same way

###Password Salting
	- Makes it impossible to use lookup and rainbow tables to crack a hash
	- Append or prepend a random string (salt) to the password
	- To check if a password is correct, we need the salt, so it is usually stored in the account database
	- Does not need to be secret - because hacker doesn't know in advance what the salt will be, cannot create a lookup or rainbow table
	- If each user's salt is different, reverse lookup tables won't work either

###Common pitfalls with password salting
	- salt reuse
	- short salt (should be at least 32 random bytes)
	- using username as the salt

###Hashing pitfalls
	- combining multiple hashing algorithms (it's easy to reverse engineer, so doesn't really offer extra protection)
	- trying to invent your own crypto

###Proper hashing technique
	- Generate salt using a "Cryptographicall Secure Pseudo-Random Number Generator" (CSPRNG)
		- Don't want salt to be predictable
		- C#: System.Security.Cryptography.RNGCryptoServiceProvider
	- Generate salt per-user per-password
	- Salt should be at least as long as the generated hash
	- Storing a password:
		- Generate salt using CSPRNG
		- prepend salt to password and hash it using standard crypto hash function
		- Save both salt and hash in user's database record
	- Validate a password:
		- Retrieve salt and hash from database
		- prepend salt to given password and hash it using the same hash function
		- Compare the hash of given password to hash in the database. If they match, password is correct.
	- Always hash on the server
		- if you hash on the client, the hash becomes the user's password
		- if you hash on the client, ALWAYS also hash on the server
		- password hashing on the client is not a substitute for HTTPS
		- Client side hashes should be salted too, but don't make send the server salt to the client.
			Instead you can use username + site-specific string (just on client) as the salt)

###Slow hash functions