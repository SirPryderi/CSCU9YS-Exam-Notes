Security And Forensics
===================

Table of Contents
------------------------

Chapters to read
-----------------------
1,9,10,12

Encryption - DES
See SiC, p68-72 & p733-748
Encryption - AES
See SiC, p72-75 & p748-754
Encryption - RSA
See SiC, p77-78, p767-773 

Adversaries and Attacks
---------------------------------
aka _How to become a scammer in 419 steps_.

### Adversaries
- Individuals
    - Hackers/Crackers ─ Curiosity/Amusement
    - Lone Criminals ─ Financial Gain
    - Insiders ─ Revenge, Financial Gain
- Organizations
    - Business ─ Industrial Espionage
    - Organized crime ─ Financial Gain
    - Terrorists ─ Information Gain, Financial Gain, Attack Infrastructures
    - Governments ─ Surveillance

### Attacks
- Criminal
    - Fraud
        - Scams Emails
            - 419 scam
            - Advance-fee scam
        - Phishing
            - Fake websites to steal credentials
        - Virus
     - Damage
         - Motivated by, terrorism, malice and revenge
         - Shutdown of infrastructure
         - Deletion of data
    - Intellectual Property Theft
        - Theft of design documents, source code, patents, etc.
        - Warez websites for multi-media
    - Identity Theft
        - Steal personal information to carry out further offence
    - Data Theft
        - Steal confidential information from websites where it is normally stored
- Privacy
    - Surveillance
        - Monitoring a user activity to retrieve useful information
    - Traffic Analysis
        - Monitoring a user activity to find navigation pattern between websites
- Adverse Publicity
    - Denial of Service
    - Blackmail
    - Website Defacement

Secure System Requirements
-----------------------------------------
A secure system is comprised of:
- Privacy
- Anonymity
- Authentication
- Authorisation
- Integrity
- Audit

### Privacy
Privacy is "_a state of being free from being observed or disturbed by others_".

#### Privacy in the society
Prior to the internet days, it was hard to find data (especially personal), because of the difficulty of obtaining it. Now it is extremely easy do surveillance on someone, from both individuals and organisations.

The concept of privacy varies from country to country and person to person.

In the E.U. the personal data is owned by you, and companies are not allowed to sell it. Conversely, in the U.S. the company owns it, and it can be sold to other companies (for profit, marketing, etc.).

It is important to be aware of privacy issues, as our decision might shape what will be of our personal information in the future. The E.U. seems to be on the right way for now, good job us! :)

##### Data Protection Act (DPA)
The Data Protection Act is designed to protect citizens' privacy and enforce how organisations handle information relating to them.

The DPA can be summarised in eight principles:
- Data should be fairly and lawfully obtained
- It should be held only for a specific and lawful purpose
- It should be relevant to the task
- It should be accurate and up to date
- It should not be kept for longer than necessary
- It should be processed in accordance to the rights of the owner
- It should be kept securely and not misused
- It should not be transferred out of the European Economic Area, unless the destination has an equivalent level of data protection

##### Regulation of Investigatory Act (RIPA)
In contrast with DPA, RIPA allows government agencies to monitor citizen's activities, if they are suspected of a crime. It imposes the ISP to keep browsing history, and allows said agencies to access it at any time.

##### General Data Protection Regulation (GDPR)
GDPR is a regulation in EU law that:
- gives control to the individuals over their personal data
- simplifies the regulatory environment for internation business unifying the regulation within the EU.

##### Data mining
Big software companies like Google and Facebook make most of their profit by using user's data to make targeted advertisements, and selling the data to interested parties.

### Anonymity
"_The situation in which someone's name is not given or known._"
- Removes bias
- Allows whistleblowers to reveal details without fear
- Removes trust barriers

Anonymity can be useful to guarantee the privacy of users, on the other hand it can be easily exploited by people with malicious intent.

### Authentication
Authentication is the process of identifying an individual as being genuine and not an impostor.

- An **individual** is a unique person
- An **identity** is a character string or a similar descriptor 
    - it doesn't have to belong to one individual
    - entitles an individual with certain actions
- An **attribute** is a characteristic of an identity

Common types of authentication mechanisms (identity authentication) checks if an individual:
- **knows**
    - Password, PIN, date of birth, mother's date of birth (!)
- **has**
    - Card, key, uniform, badge, ID
- **is**
    - Face, fingerprint, iris scan

Authenticating an individual is not particularly simple, on the other hand, as it relies on documents and from other people.

Authentication might affect your privacy, as it is simple to collect data from multiple sources that can be linked to a specific individual (credit cards, loyalty cards, bus cards, etc.)

### Authorisation
Authorisation restricts what an authorised identity can make.

This is to protect the systems and data from the users.

### Integrity
Integrity is concerned with ensuring that information is genuine and has not been tampered with.

In modern days it easy extremely easy to forge and manipulate the truth with fake media. It is important to understand what is true, and what is not.
One way of achieving this is __accountability__ or __auditing__, knowing when who has done what.

### Audit
Auditing is the process of conducting a systematic review of something.

In computer terms, it requires logging and recording all the actions the users have done on the system.

This can be useful to have an history of the files, but also to find trails left by users with malicious intent. An audit mechanism also acts as deterrent.

Audit logs can still be hacked and covered by skilled attackers.

Computer Forensics
----------------------------
Computer forensics is the practice of collecting, analysing and reporting on digital data in a way that is legally admissible. It can be used in the detection and prevention of crime and in any dispute where evidence is stored digitally.

A **digital evidence** is any piece of information being subject to human intervention or not, that can be extracted from a computer, that is presented in a human-readable format.

Computer forensics is used by:
- Criminal prosecutors
    - to prosecute suspects and use evidence
- Civil litigations
    - use of digital evidence in civil cases
- Insurance companies
    - use digital evidence to find frauds
- Private corporations
    - use digital evidence to civil cases (harassment, fraud, embezzlement)
- Law Enforcement Officials
    - use computer forensics to backup search warrants
- Individuals
    - use of digital evidence as support of civil cases

Cryptography
-------------------
Cryptography is the study and practice of **protecting information** by **data encoding** and **transformation techniques**.

Encryption allows to:
- hide information (privacy)
- authenticate information
- guarantee integrity

Cryptography plays an important role in **identity authentication** (passwords, certificates).

Cryptography is also important in **data integrity**, as digital data can be associated with a (short) digital fingerprint, that will change even if one bite has been altered (hash/checksum).

#### Terminology
- `S` - Sender
- `P` - Plaintext
- `E` - Encryption/Encipher function
- `C` - Encrypted text
- `D` - Decryption/Decipher function
- `R` - Receiver

### Symmetric and Asymmetric Encryption
Encryption method can use one more more keys $$K$$ to so that:

$$C = E(K, P)$$

An algorithm where $$C = E (K, P),\ P = D(K, C)$$ is defined **symmetric**. In other words, the same key $$K$$ can be used for both encryption and decryption.

Conversely, algorithms that follow the rule $$C = E (K_1, P),\ P = D(K_2, C),\ K_1 ≠ K2$$ are known as **asymmetric**. They can be more secure in certain circumstances (opening a secure channel). Asymmetric encryption is very computationally taxing.

### Cryptographic Algorithms
A **cipher** is an algorithm for performing encryption or decryption, a series of well-defined steps that can be followed as a procedure.

// TODO Covers this in more details!

- Rotation ciphers
- Substitution ciphers
- Book ciphers
- Transportation ciphers
    - Route ciphers
    - Columnar Ciphers

### Cryptanalysis — Cryptographic Attacks

**Cryptanalysis** is the process of breaking ciphers. 

There are a few ways of breaking a cipher:
- Recognise patterns in text
- Infer meaning by noting communication patterns
- Find the decryption key
- Find mathematical weaknesses of the cipher and exploit them (brute force?)

Any algorithm is theoretically breakable, but in practice an algorithm that would take too long to decipher is considered **unbreakable**.

Symmetric and asymmetric algorithms have different vulnerabilities:

- **Symmetric**
    - Brute force
    - Common patterns
- **Asymmetric**
    - Known algorithm
        - Challenge is to find the key

Looking for patterns is a very effective way against substitution ciphers.

For a given language, the frequency of letters and words is known. This can be used to guess which character/word is which, allowing to progressively make a decryption algorithm, trying a small set of substitutions until they make sense. One-time pads and book ciphers are particularly effective against common patterns exploitation.

### Creating Encryption Algorithms
#### Shannon's Rules
- Required secrecy should determine effort involved in encryption/decryption
- The set of possible keys should be simple and relatively unrestricted
- The implementation of the encryption algorithm should be as simple as possible
- Errors introduced in the cipher process should not propagate and corrupt the rest of the message
- The size of the cipher should not be larger than the plaintext

#### Stream vs Block Ciphers
There are two main types of ciphers: **stream ciphers** and **block ciphers**.

**Stream ciphers**
- Encipher plain text one character at a time
- Do not require the complete message to encrypt
- Useful for secure channels (streams)

**Block ciphers**
- Block ciphers encipher the whole block of plain text
- Required the data to be collated in chunks
    - Some require the whole plaintext to encrypt
    - They don't leave patterns in the text

**#### Confusing vs Diffusing
There is also a distinction between **confusing** vs **diffusing** ciphers.

**Confusing ciphers**
- Changing one plaintext letter should not enable a cryptanalyst to determine the effect on cipher text
- Substitution ciphers are not confusing
- One-time pads and book ciphers are confusing

**Diffusing ciphers**
- Aims to spread the plaintext information throughout the cipher text
- Higher diffusion requires longer cipher text to be broken

#### Comparison Matrix

|               | Stream                       | Block                           |
| ------------- | ---------------------------- | ------------------------------- |
| Advantages    | Speed, low error propagation | Strong diffusion                |
| Disadvantages | Weak/no diffusion            | Slow, weak to error propagation |

### Using Encryption
#### Commercial Encryption
Commercial-grade encryption should:
- Be derived from solid mathematical principles
- Analysed and tested – peer review
- Withstand repeated real world usage

Currently used commercial-grade encryption algorithms:
- Symmetric
    - **DES** — Data Encryption Standard
    - **AES** — Advanced Encryption Standard
- Asymmetric
    - **RSA** — Rivest-Shamir-Adelman

##### Data Encryption Standard (DES)
DES is a **symmetric** key cipher with a 56 bit private key.

Method:
- Applies 16 iterations of substitution and diffusion
- Uses standard arithmetic and logical operators
- Suitable for operations on a standard PC or chip
- Effectively weak 56 bit key

##### Advanced Encryption Standard (AES)
AES is a **symmetric** key cipher with a private key with variable length (128, 192, 245 bits)

Advantages:
- Fast
- Substitution and Transportation
- Repeat cycles of 10, 12, 14

Method:
- 128 bit blocks use 8 bit substitution — diffuses data
- Logical shift — creates a transposition
- Shift and Exclusive $$OR$$ — adds both confusion and diffusion
- Add sub key element – adds confusion and introduces key binding

##### RSA
RSA is an **asymmetric** cipher, using a set of **public** and **private** keys.

In RSA:
- $$P = E(D(P, e), d) = D(E(P, d), e)$$
- $$C = E(P) = P^e\ mod\ n$$
- $$P = D(C) = (P^e)^d\ mod\ n$$
Where $$e$$ and $$d$$ are the two keys.

#### Hash Functions
#### Key Exchange
#### Digital Signatures
#### Certificates
#### Trust

Securing Software
--------------------------

Rogue Software
----------------------

Network
------------