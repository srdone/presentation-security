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
- Stanford JavaScript Crypto Library: http://bitwiseshiftleft.github.io/sjcl/

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
- PBKDF2, bcrypt
- Makes DoS attacks easier
- client side: PBKDF2 in Stanford JavaScript Crypto Library

###Dos and Don'ts
- Don't use outdated hash functions (MD5 or SHA1)
- Don't use insecure versions of crypto libraries
- Don't design algorithms yourself - very good ones already exist in the public domain
- Use well tested hash algorithms
- If you allow the user to reset their password, make sure you expire the token:
	- as soon as they log in successfully
	- within 15 min of sending it
	- immediately after it is used
- Avoid user fatigue with too-frequent password reset requirements
- Recommend to users that they use unique passwords for each site

###Hashing implementation notes
- Use of slowequals to prevent timing attacks

#SQL Injection Attacks
- insertion or injection of a SQL query via the input data from the client to the application

C# code example:
    string userName = ctx.getAuthenticatedUserName();
	string query = "SELECT * FROM items WHERE owner = "'" 
					+ userName + "' AND itemname = '"  
					+ ItemName.Text + "'";
	sda = new SqlDataAdapter(query, conn);
	DataTable dt = new DataTable();
	sda.Fill(dt);

Query is intended to be:
	SELECT * FROM items
	WHERE owner = 
	AND itemname = ;

If user enters string `'name' OR 'a' = 'a'` then query becomes:
	SELECT * FROM items
	WHERE owner = 'wiley'
	AND itemname = 'name' OR 'a'='a';

Which is logically the same as:
	SELECT * FROM items;
	
###Prevention of SQL injection attacks
- Tranditionally handle them as input validation problems and only accept characters from a whitelist, or identify and escape malicious values
- Stored procedures can prevent

#OWASP - Open Web Application Security Project


#Cross-site request forgery (below from Wikipedia)
- exploits the trust the site has in the user's browser
- unauthorized commands transmitted from a user that the website trusts
- forged login requests (login CSRF)
- Cross-site Scripting allows attackers to bypass most CSRF preventions

##Example
Mallory crafts an HTML image element that references an action on Alice's bank's website and posts it on a chat forum
If the account access is stored in a cookie that has not expired, loading the image will call the action on alice's account
Happens with web apps that perform actions based on input from trusted and authenticated users without requiring the user to authorize the action

##Requirements for CSRF to be successful
- Target must be a site that doesn't check the referrer header or a browser that allows referer spoofing
- Attacker must find a form submission or url with side effects that does something (transfers money, changes email address)
- Attacker must determine all the right values for the forms or URL inputs, including ones that might be secret authentication values
- Attacker must lure the victim to a web page with malicious code while the victim is logged into the targe site
- Note that the attack is blind, but are easy to mount and are invisible to the victim.

##Prevention

###Synchronizer token pattern
A token, secret, and unique value for each request embedded by the application in all HTML forms and verified on the server
Difficult to implement in applications that make heavy use of AJAX, but is very compatible

###Cookie-to-Header Token
On login, application sets a cookie with a random token that remains the same for the session, the JavaScript reads the value
and copies it into a custom HTTP header sent with each request, and the server validates the presence and integrity of the token
Implemented by Django and AngularJS. Remains constant over the whole session, works well with AJAX applications, does not enforce
sequence of events in the application

###Client side safeguards
Some browser extensions exist, but can cause incompatibilities

###Other techniques
- Verifying that request headers contain correct Referer or Origin headers, but with the correct combination of extensions these can be spoofed.


#Cross-site scripting (below from Wikipedia)
- Allows attackers to inject client-side script into web pages viewed by other users.
- Can be used to bypass access controls such as the same-origin policy
- Most commonly reported security vulnerability

###Types
- Reflected (non-persistent)
Taking query parameters or form submissions and displaying the results in HTML without properly escaping characters
React automatically protects agains this attack
- Persistent
Data provided by the attacker is saved by the server, and then displayed in the browser without proper HTML escaping

###Browser Exploitation Framework
Open source penetration testing tool


#Clickjacking (from Wikipedia)
Transparent web page overlayed on a different page, so that when a user thinks they are clicking on one thing,
they are actually clicking on another.

###Prevention
Client-side: NoScript, GuardedId, Gazelle
Server-side: Framekiller, X-Frame-Options, Content Security Policy

####Frame Ancestors
	# Disallow embedding. All iframes etc. will be blank, or contain a browser specific error page.
	Content-Security-Policy: frame-ancestors 'none'
	
	# Allow embedding of [[same-origin policy|own content]] only.
	Content-Security-Policy: frame-ancestors 'self'
	
	# Allow specific origins to embed this content
	Content-Security-Policy: frame-ancestors example.com wikipedia.org


#Input Validation
Checking input to make sure it falls within parameters
Can prevent XSS & SQL Injection attacks
Good to validate data anyway so users know when they haven't saved things properly

#PII/PHI
Personally identifiable information
Protected health information

We need to keep these kinds of information secure - prevent ID theft and legal consequences
Should mask whenever possible in the UI - users should not see information they don't need
Use unique ids generated by the company instead of SSN, for example
You can figure out an SSN if you have the birth date, state of birth, and last 4 digits of the SSN
The first 5 digits are based on date of birth and state where born