<p align="center">
  <img src="forest.png" alt="Forest Logo" width="220"/>
</p>

**Forest** (aka Secure Sharded Storage System/4S) offers a powerful and modern solution for data security, meticulously blending physical safeguards with cutting-edge encryption, based on inherent designs of RAID, and token-centric security models. Engineered for users and organizations seeking a resilient, user-controlled, and highly secure storage system, Forest is implemented in Rust for improved performance and safety. It also features local and/or cloud storage in tandem with a physical USB key, PINs, and passwords, creating multiple layers of defense for your sensitive data, protecting from unauthorized access, data breaches, tampering, malware, and loss due to single-point hardware failure.

---

## Key Components

### **Main Storage:**
- Serves as the primary repository for the bulk of your encrypted data.
- Compatible with local HDDs/SSDs or cloud-based storage services (e.g., S3, Google Drive, Dropbox), offering flexibility in deployment.
- Stores encrypted data shards and encryption keys/metadata necessary for data reconstruction.

### **USB Key (The 'Root Key'):**
- A standard USB flash drive (or any portable storage medium). Once formatted, the physical device will be known as the **'Root Key'**.
- Securely holds private encryption keys, key derivation secrets, and a dedicated shard of the user's data.
- **PIN/Password Protection:** Access to the Root Key's sensitive functions, keys, and data is gated by a user-defined PIN or password. This credential undergoes key derivation and hashing using **Argon2id and SHA3_512**, the gold-standard memory-hard function, as well as the widely accepted and proven quantum-resistant SHA3_512, to provide maximum resistance against brute-force and dictionary attacks.
- **Hardware Security Recommendation:** For optimal security, Forest is designed to leverage, and strongly recommends the use of, USB drives equipped with a **secure element (SE)** or **hardware security module (HSM)**. Such keys can perform cryptographic operations internally and prevent private key material from ever leaving the tamper-resistant chip, even if the host computer is compromised.

### **Forest Software Application:**
- A standalone, client-side application that orchestrates the entire system.
- Manages data sharding, encryption/decryption processes, key management, and authentication.
- Interacts with storage and the Root Key via a local API, minimizing attack surface by avoiding direct web server exposure for core operations (unless cloud storage is explicitly configured).

---

## How It Works: Data Management & Advanced Security

Forest's architecture is founded on strong cryptographic principles to ensure confidentiality, integrity, and availability.

### **Data Sharding:**
- Data is intelligently fragmented into multiple shards. These shards are distributed across the Main Storage and the Root Key(s).
- This strategy ensures that no single storage location (if compromised) yields the complete dataset, significantly increasing data security. The software seamlessly reassembles shards for authorized access.

### **Encryption & Integrity:**
- **Primary Encryption:** Data is encrypted using **XChaCha20-Poly1305**. This is an AEAD (Authenticated Encryption with Associated Data) cipher.
  - **XChaCha20:** Provides high confidentiality with an extended (192-bit) nonce, making random nonce generation exceptionally safe and virtually eliminating the risk of nonce reuse with the same key.
  - **Poly1305:** Generates a message authentication code (MAC) to ensure data integrity and authenticity, protecting against tampering and unauthorized modifications.
- **Key Management & Derivation:**
  - **Hardware-Based Authentication:** The Root Key UUID is integrated into the Key encryption process, ensuring that even a cloned Root Key cannot be used on a different drive without the matching UUID, not including verified backups of the Root Key. This approach adds an extra layer of protection against unauthorized access while maintaining a seamless user experience.
  - Master keys are protected by the Root Key. The user's Forest/Burn Keys decrypt a Key Encryption Key (KEK) stored on the Root Key. This KEK then encrypts/decrypts Data Encryption Keys (DEKs) which are used for the actual data shards.
  - The principles of hybrid encryption, akin to those in **ECIES (Elliptic Curve Integrated Encryption Scheme)**, guide the secure exchange and protection of symmetric DEKs using asymmetric cryptography tied to the Forest Key.
- **Key Types:**
  - There are 3 types of keys: a **Forest** Key, **Burn** (burn/ember/smoke) keys, and a **Seed** key, each explicitly hashed separately.
    - The Forest key is the main user-defined secret that serves as the primary key to unlock and access the data.
    - The Burn key is a user-defined secret that triggers the secure erasure of all data. (optional)
    - The Ember key is an alternate Burn key that serves to allow a one-time viewing of the data, then those particular shards are securely wiped. (optional)
    - The Smoke key is an alternate Burn key that displays the decoy environment and decoy data. (optional)
    - The Seed key is an additional key to add on to the end of any key, designed to secretly backup the data to a cloud server, in addition to your standard key procedure. (optional)
- **Important Considerations for Key Usage:**
  - **Proper Syntax:** (Forest Key) OR (One of: `Burn Key` OR `Ember Key` OR `Smoke Key` OR [Your `Smoke Key` secret + Your `Ember Key` secret]) + (Optionally, `Seed Key` at the end)**
    - **Examples of Input Strings:**
      - To access your data normally: `ForestSecret` : `Forest`
      - To access data AND trigger the seed action: `ForestSecretSeedSecret` : `Forest77`
      - To trigger complete data erasure: `BurnSecret` : `Delta`
      - To trigger data erasure AND the seed action (e.g., log erasure attempt): `BurnSecretSeedSecret` : `Delta77`
      - To access the decoy environment: `SmokeSecret` : `Mirage`
      - For a one-time view of the decoy environment: `SmokeSecretEmberSecret` : `MirageFire`
      - For a one-time view of the decoy environment AND seed action: `SmokeSecretEmberSecretSeedSecret` : `MirageFire77`
      - For a one-time view of real data: `EmberSecret` : `Fire`
    - All distinct key secrets (Forest, Burn, Ember, Smoke, Seed) must be unique, enabled, and securely pre-configured during the initial Forest system setup.
  - **Burn Key Override Principle:** If the `Burn Key` secret is part of your input, its secure erasure function takes absolute precedence. Any `Ember Key` or `Smoke Key` functions implied by other parts of the input will be overridden by the data destruction process.
  - The exact sequence of concatenated secrets is critical for invoking combined operations.
  - Given the power of these keys, especially Burn and concatenated variants, extreme care, precise memory, and understanding of each function are vital. Accidental data loss is possible if keys are misused.
  - If using the Seed Key for network-based actions, be mindful of the security implications of potential network traffic monitoring, as noted in the main security considerations.
- **Burn Keys:** Burn/Smoke Keys are Forest Keys designed to secretly trigger specific security mechanisms for data protection/destruction.
  - **Utter Destruction Mechanism:**
    - Secure Erasure: Upon triggering with a Burn/Ember key, the system will securely erase all keys and data shards, ensuring irreversibility. This involves standards like DoD 5220.22-M.
    - *This feature is a last resort and is irreversible. Extreme caution is advised.*
  - **Plausible Deniability Mechanism:**
    - Decoy Environment: For Smoke keys, unlock a hidden encrypted decoy environment volume on the same Root Key that appears legitimate. This involves:- Utilizing sophisticated encryption techniques or hidden partitions.
    - Ensuring access to these decoy elements is only possible with the correct password, effectively fooling potential attackers.

### **Redundancy & Recovery:**
- The system supports the creation of secure backups for the Root Key's critical data (e.g., encrypted key material, its data shard). This is absolutely necessary for disaster recovery and preventing data loss if a Root Key is lost or damaged. Recovery past this is IMPOSSIBLE.

---

## Core Security Features

### **Multi-Layer Authentication:**
- **Baseline:** Requires the physical presence of the authenticated Root Key and its correct PIN/password (strengthened by **Argon2id and SHA3_512**).
  - The use of **Argon2id and SHA3_512** uses brute-force preventative and quantum-resistant methods to securely keep your secrets secret.
- **Optional Multi-Device/Multi-Share Authentication:** For enhanced security, Forest can be configured to require multiple authentication factors or devices.
  - This can involve distributing a master secret or key across multiple Root Keys or other compatible devices (e.g., a smartphone app acting as a secure authenticator).
  - Utilizes **Shamir's Secret Sharing (SSS)**, allowing a secret to be split into `n` shares, where any `k` (threshold, `k <= n`) shares are required to reconstruct the secret. This provides both security (no single share is sufficient) and redundancy (loss of some shares up to `n-k` can be tolerated).

### **Mandatory USB Key Presence:**
- The Forest software will not grant access to the main data store or perform decryption without a successfully authenticated Root Key.

---

## Software Functionality

### **Local-First Operation:**
- Designed to operate primarily on the user's local machine, reducing reliance on external servers for core security operations.

### **User Interface (UI):**
- Aims for a modern, clean, and intuitive user experience. Features like dark mode and accessibility considerations are integral to the design.

### **Automatic Data Handling:**
- Upon successful authentication of the Root Key, the software automatically handles the decryption and reassembly of data shards for seamless user access.

---

## Setup & Configuration

### **Guided Setup Wizard:**
- A step-by-step wizard simplifies the initial setup process, including Root Key initialization, Main Storage configuration, and data distribution preferences.

### **Customizable Security Parameters:**
- While providing sensible defaults, advanced users can have options to fine-tune certain security parameters where appropriate and safe.

---

## Performance & Scalability

### **Optimized Efficiency:**
- The choice of **XChaCha20-Poly1305** ensures high-speed encryption and decryption, minimizing performance overhead on modern hardware.

### **Scalable Architecture:**
- Designed to accommodate growing data volumes and the potential integration of multiple Root Keys or devices in multi-share configurations.

---

## Usability

### **Intuitive Design:**
- Focuses on ease of use, ensuring that powerful security does not come at the cost of a complicated user experience.

### **Clear Instructions & Feedback:**
- The software will provide clear guidance and feedback to the user throughout its operation.

---

## Key Considerations & Best Practices

1. **Master Key Security:** The entire security of Forest hinges on the protection of its master encryption keys. The use of **Argon2id and SHA3_512**, **Shamir's Secret Sharing**, **hardware secure elements** on USB keys, and **sound cryptographic practices** are all aimed at this.
2. **Physical Security of Root Key(s):** While cryptographically protected, the physical security of the Root Key(s) remains crucial. Treat them as you would any high-value physical key.
3. **Backup Strategy:** Regularly and securely back up your Root Key's essential recovery data. Store backups in a physically separate and secure location.
4. **User Education:** Users must understand the importance of their PIN/password, the implications of the Burn keys, and general security hygiene.
5. **Third-Party Integrations (if any):** If the local API is used for integration with other applications, ensure those integrations adhere to strict security protocols.
6. **Burn Key Prudence:** The emergency data destruction feature is powerful and final. Understand its function completely before enabling or using it.

---

## Todo

### **Hardware-Backed Keys on USB:**
- **Suggestion:** For ultimate USB key security, explore using USB devices that have **secure elements or HSM-like capabilities** (e.g., FIPS 140-2 certified drives, or smart card-based USB tokens).
- **Why:** This allows the private encryption key(s) to be generated and stored within a tamper-resistant chip on the USB device itself. The key never leaves the chip; cryptographic operations (like decryption or signing) happen *on* the chip. This protects against malware on the host computer trying to steal the key.
