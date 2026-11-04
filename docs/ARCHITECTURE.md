# Architecture and System Design

## 1. Overview and Design Principles

The Secure Password Manager is built as a layered, decoupled C++20 application prioritizing cryptographic correctness, memory safety, clean separation of concerns, and robust error management.

The architecture strictly separates user interaction, domain logic, cryptographic operations, and disk persistence. No layer bypasses intermediate abstractions.

```mermaid
flowchart TD
    subgraph UI_CLI["CLI & Presentation Layer"]
        App["PasswordManagerApp (CLI Controller)"]
        Console["Console (Win32 Masking, Scrubber, EchoGuard)"]
        Banner["UI Banner & Formatters"]
    end

    subgraph DOMAIN["Domain & Business Logic Layer"]
        Vault["Vault (In-Memory Credential Store)"]
        CredModel["Credential & CredentialInput Models"]
        Validator["CredentialValidator"]
        Clock["IClock / SystemClock"]
    end

    subgraph CRYPTO["Cryptographic & Security Layer"]
        Crypto["CryptoService (Argon2id + XChaCha20-Poly1305)"]
        SecKey["SecureKey (Guarded Key Memory)"]
        SecBuf["SecureBuffer (Guard-Paged Plaintext Memory)"]
        PassGen["PasswordGenerator (libsodium CSPRNG)"]
    end

    subgraph PERSIST["Persistence & Serialization Layer"]
        Storage["VaultStorage (Atomic Replace, Flush)"]
        Serializer["VaultSerializer (JSON + Binary SPMV Header)"]
        Header["VaultHeader (Endian-Safe Binary Spec)"]
    end

    App --> Console
    App --> Banner
    App --> Vault
    App --> PassGen
    App --> Storage

    Vault --> CredModel
    Vault --> Validator
    Vault --> Clock

    Storage --> Serializer
    Storage --> Crypto
    Serializer --> Header
    Serializer --> SecBuf
    Crypto --> SecKey
    Crypto --> SecBuf
```

---

## 2. Component Layers and Responsibilities

### 2.1 CLI & Presentation Layer (`password_manager::cli`, `password_manager::ui`)
- **`PasswordManagerApp`**: Orchestrates application lifecycle, menu navigation, unlock/create workflows, session state (`is_unlocked_`, `has_unsaved_changes_`), and action dispatch.
- **`Console`**: Provides platform-abstracted console I/O, Win32 terminal echo suppression (`ConsoleEchoGuard`), masked password inputs, stream redirection for tests, and zeroization helpers (`ScopedStringScrubber`, `secure_zero_string`).
- **`ui::display_welcome_banner`**: Renders version, build configuration, and application branding.

### 2.2 Domain & Core Layer (`password_manager::core`, `password_manager::models`)
- **`Credential`**: Immutable record representation holding `id`, `service`, `username`, `password`, `url`, `category`, `notes`, `created_at`, and `updated_at`.
- **`CredentialInput`**: User-supplied input transfer structure validated before credential instantiation.
- **`Vault`**: In-memory repository managing credentials, unique ID generation, duplicate detection, and search operations. Operates purely in memory with zero knowledge of disk or cryptography.
- **`CredentialValidator`**: Enforces service name non-emptiness, password presence, length limits, and URL syntax validation.
- **`IClock` / `SystemClock`**: Time abstraction providing ISO-8601 UTC timestamp generation and deterministic time mocking in unit tests.

### 2.3 Cryptographic Security Layer (`password_manager::core`)
- **`CryptoService`**: High-level cryptographic interface utilizing libsodium primitives exclusively:
  - Argon2id v1.3 password-based key derivation.
  - XChaCha20-Poly1305-IETF authenticated encryption with 192-bit extended nonces.
  - Verification of 48-byte Additional Authenticated Data (AAD).
  - CSPRNG random generation for salts and nonces.
- **`SecureKey`**: RAII wrapper encapsulating a 32-byte symmetric key inside an inline stack buffer (`std::array<unsigned char, 32>`). Automatically scrubbed via `sodium_memzero` on destruction and move. Move-only semantics prevent accidental copies.
- **`SecureBuffer`**: Dynamic-length sensitive data container backed by `sodium_malloc` page-protected memory.
- **`PasswordGenerator`**: Cryptographically secure password generation with configurable lengths, character sets, guaranteed category representation, and Fisher-Yates uniform shuffle.

### 2.4 Persistence & Serialization Layer (`password_manager::core`)
- **`VaultStorage`**: High-level persistence coordinator managing:
  - Header inspection and validation.
  - Vault file loading, decryption, and authentication.
  - Vault encryption and atomic replacement via Win32 `ReplaceFileW` and `FlushFileBuffers`.
- **`VaultSerializer`**: Converts between in-memory `Vault` instances and binary payloads. Handles JSON serialization/deserialization into `SecureBuffer` and binary `VaultHeader` formatting.
- **`VaultHeader`**: 80-byte fixed-size binary specification with little-endian encoding, algorithm identifiers, KDF parameters, and AAD bounds.

### 2.5 Error Handling Architecture (`password_manager::core`)
- **`Result<T>`**: Value-or-error vocabulary type (`std::variant`-based) enforcing explicit error propagation without exceptions across cryptographic boundaries.
- **`VaultError`**: Strongly typed error record pairing `VaultErrorCode` with descriptive context.

---

## 3. Credential Lifecycle & Data Flow

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant App as PasswordManagerApp
    participant Console as Console
    participant Storage as VaultStorage
    participant Crypto as CryptoService
    participant Serializer as VaultSerializer
    participant Vault as Vault

    Note over User,Vault: 1. Vault Unlock Sequence
    User->>App: Launch application with vault path
    App->>Storage: inspect_header(path)
    Storage-->>App: VaultHeader (valid)
    User->>Console: Enter master password (masked)
    Console-->>App: Master password string
    App->>Storage: load_vault(path, password)
    Storage->>Crypto: derive_key(password, salt, kdf_params)
    Crypto-->>Storage: SecureKey
    Storage->>Crypto: decrypt(ciphertext, nonce, key, AAD)
    Crypto-->>Storage: SecureBuffer (decrypted JSON)
    Storage->>Serializer: deserialize_vault(buffer)
    Serializer->>Vault: Instantiate and populate credentials
    Serializer-->>Storage: Vault instance
    Storage-->>App: Result<Vault>
    App->>Console: Zeroize master password string via Scrubber
    App-->>User: Display Main Menu (Unlocked)

    Note over User,Vault: 2. Credential Add & In-Memory Update
    User->>App: Option 1: Add Credential
    App->>Console: Prompt service, username, password, notes
    Console-->>App: CredentialInput
    App->>Vault: add_credential(input)
    Vault-->>App: Result<Credential> (Assigned ID + Timestamps)
    App->>App: Set has_unsaved_changes_ = true

    Note over User,Vault: 3. Atomic Save Sequence
    User->>App: Option 8: Save Vault
    App->>Storage: save_vault(path, vault, session_key)
    Storage->>Serializer: serialize_vault(vault)
    Serializer-->>Storage: SecureBuffer (JSON plaintext)
    Storage->>Crypto: encrypt(buffer, key, AAD)
    Crypto-->>Storage: EncryptedMessage (Ciphertext + Tag)
    Storage->>Storage: Write to temporary file (.spm_*.tmp)
    Storage->>Storage: FlushFileBuffers(hTemp)
    Storage->>Storage: ReplaceFileW(target, temp, REPLACEFILE_WRITE_THROUGH)
    Storage-->>App: Result<void> (Success)
    App->>App: Set has_unsaved_changes_ = false

    Note over User,Vault: 4. Vault Lock / Session Exit
    User->>App: Option 9: Lock Vault
    App->>App: Reset session_key_ (SecureKey wiped)
    App->>App: Reset vault_ (Credentials freed)
    App->>App: Reset vault_header_ (Salt/Nonce cleared)
    App->>App: Set is_unlocked_ = false
    App-->>User: Return to Unlock Screen
```

---

## 4. Key Design Decisions and Security Rationales

1. **Move-Only Cryptographic Buffers (`SecureKey`, `SecureBuffer`)**:
   - *Rationale:* Copying cryptographic keys or plaintexts across heap/stack buffers increases the attack surface for memory dumps and cold-boot inspections. `SecureKey` and `SecureBuffer` explicitly delete copy constructors and copy assignment operators.
2. **Explicit Binary Header as AAD**:
   - *Rationale:* The first 48 bytes of the vault file (version, magic, cipher ID, KDF limits, and salt) are bound to the Poly1305 MAC as Additional Authenticated Data. Any file manipulation of KDF limits or downgrade attacks breaks MAC verification immediately.
3. **Double-Ended File Flush and Atomic Replacement**:
   - *Rationale:* Writing directly to the active vault file leaves credentials vulnerable to truncation during power failures. Saving to a temporary file on the same volume followed by `FlushFileBuffers` and `ReplaceFileW` ensures write-through durability before pointer swap.
4. **Zero Heap Duplication on Password Reveal**:
   - *Rationale:* Revealing passwords streams directly to the output without allocating intermediate concatenated heap strings.
5. **No Exception Propagation Across Crypto Boundaries**:
   - *Rationale:* Exceptions can leak internal state and cause untracked unwind copies of sensitive buffers. All domain and crypto boundaries return `Result<T>` with strict status checks.
