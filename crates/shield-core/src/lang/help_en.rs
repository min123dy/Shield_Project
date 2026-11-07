//! English help texts (same structure as help_ko.rs).

use crate::help::{Rows, Sections};

pub const ENC_USAGE: Sections = &[
    (
        "Quick start (encryption)",
        &[
            "1. Press [Choose file\u{2026}] or [Choose folder\u{2026}], or drop a file or folder on the window. (Dropping a .shd file switches to the Decrypt tab.)",
            "2. Type the password twice. Adding a key file makes it stronger.",
            "3. Leave the PIM at its default. If you change it, write the number down.",
            "4. The compression strength is under [Advanced options]. 'Auto' is recommended.",
            "5. Press [Start encryption] at the bottom: fix list -> compress -> encrypt -> verify the restore. The result file only appears when the verification passes.",
            "6. A password under 12 characters or with a common pattern shows the reasons and asks once more. The default button is [Cancel].",
        ],
    ),
    (
        "Decryption",
        &[
            "1. Choose the .shd file and enter the same password, PIM and key files that were used to encrypt it.",
            "2. The whole body is authenticated before anything is extracted, so a tampered file never produces plaintext.",
            "3. The result appears next to the .shd under its original name. An existing item is never overwritten: '(decrypted)' is added instead.",
            "4. A .shd downloaded from the internet passes its 'downloaded from the internet' mark (Zone.Identifier) on to every extracted file.",
            "5. To see the contents first or to extract only some files, open the .shd in the [File manager] window.",
        ],
    ),
    (
        "Password and key change",
        &[
            "\u{2022} Change password: the file key (DEK) is wrapped again under the new password and the old key slot is overwritten 7 times. Instant for any file size.",
            "\u{2022} Full key replacement: the whole body is re-encrypted under a new DEK, salts, nonces and padding, verified, and the file replaced atomically.",
            "\u{2022} If another Shield window is using the same file you get 'used by another task' and can press [Retry].",
            "\u{2022} Either way, older backups, cloud version history and shadow copies still open with the old password.",
        ],
    ),
    (
        "Shredding the originals",
        &[
            "\u{2022} Only the files of the list fixed before encryption are overwritten and deleted, and only while their size, time and file ID are unchanged. Hard links, links (junctions) and new files are left alone.",
            "\u{2022} Alternate data streams (ADS) are checked first. Hidden streams stop the task and you are asked whether to overwrite them too. A download mark (Zone.Identifier) alone is overwritten and noted in the result.",
            "\u{2022} Shredding only starts after the new file was reopened, fully extracted and compared with the originals (SHA3-512).",
            "\u{2022} Choose 3 passes (00, FF, random) or 7 (default in the settings). Key areas such as the header and key slots are always overwritten 7 times. TRIM runs at the end; if it fails the task still succeeds and the reason is shown.",
            "\u{2022} Before overwriting, Windows volume shadow copies (VSS) are checked and reported. Shield never deletes them (that needs administrator rights and is your decision).",
            "\u{2022} Physical erasure cannot be guaranteed on SSDs, USB sticks, shadow copies or cloud-synced folders.",
            "\u{2022} This cannot be undone. Try it on a copy first, including the decryption.",
        ],
    ),
    (
        "Important",
        &[
            "\u{2022} If the password, the PIM or a key file is lost, nobody (the developer included) can decrypt the file.",
            "\u{2022} Never edit or re-save a key file; back it up elsewhere. One changed byte makes it useless.",
            "\u{2022} With key files only and no password, anyone who has the key files can open the file.",
            "\u{2022} Passwords are limited to 256 bytes. Longer input is refused, never cut.",
            "\u{2022} After the set idle time (default 5 minutes) or when the window is minimized, typed passwords are wiped.",
            "\u{2022} Shield 3.0 uses the same file format as 2.x and opens 2.x containers. The 1.x format is not opened: decrypt such files with 1.x and encrypt them again.",
        ],
    ),
    (
        "Context menu",
        &[
            "\u{2022} The installer adds 'Encrypt with Shield', 'Decrypt with Shield' and 'Open in SHIELD' to the Explorer context menu.",
            "\u{2022} On Windows 11 they are under 'Show more options' (Shift+F10).",
            "\u{2022} With several items selected, 'Encrypt with Shield' gathers them in one window and asks whether to make one container or one per item. Items can be removed from or added to the list.",
            "\u{2022} On Linux the same entries appear in Nautilus, Nemo, Dolphin and Thunar and under 'Open with'.",
        ],
    ),
    (
        "Command line (console)",
        &[
            "\u{2022} In a terminal, shield help lists the commands: encrypt, decrypt, list, add, remove, change-password, rekey, keyfile, verify, update, entropy, version, gui.",
            "\u{2022} Passwords are read without echo. --reveal shows them on a separate screen that is cleared with the scrollback after Enter.",
            "\u{2022} Passwords as arguments (--password) are off by default; they need the setting and --allow-arg-secrets, with a warning every time. Environment variables and files are not accepted.",
            "\u{2022} Console commands never use mouse, keyboard timing or window entropy. The OS random generator is always the base.",
        ],
    ),
    (
        "Updates and integrity",
        &[
            "\u{2022} Settings > Updates: off (default), check only, or download automatically. Installing is always asked first.",
            "\u{2022} GitHub releases are checked over HTTPS; the OpenPGP signature and the SHA-256 are verified with the built-in key before anything runs. On a failure the download is deleted. Same or older versions are never installed.",
            "\u{2022} [Check program integrity] verifies the .sig next to the program. Compare the key fingerprint shown with the one the developer published.",
        ],
    ),
];

pub const MGR_USAGE: Sections = &[
    (
        "Browsing",
        &[
            "\u{2022} Type a path in the address box and press Enter, or double-click folders. [Up] goes to the parent folder, [Drives] lists the drives.",
            "\u{2022} Click selects, Ctrl+click selects several, double-click opens. Double-clicking a .shd opens it as a container.",
            "\u{2022} Drag the separators between column headers to resize columns. Hover over a cut name to see all of it.",
            "\u{2022} [Encrypt] opens the encryption window with the selected item.",
        ],
    ),
    (
        "Opening a .shd container",
        &[
            "1. Double-click the .shd, drop it on the window, or use 'Open in SHIELD' in Explorer.",
            "2. Enter the password, PIM and key files and press [Open]. A wrong password and a non-Shield file give the same message.",
            "3. Right after the list is read, the key and the password are wiped from memory. Only the list stays.",
        ],
    ),
    (
        "Inside a container",
        &[
            "\u{2022} Extract, add, remove and the integrity check ask for the password (and PIM and key files) every time. There is no 'remember for this session'.",
            "\u{2022} [Extract selected\u{2026}]: only the chosen files and folders. Each chunk read is authenticated, extracted into a private temporary folder and moved; on failure everything already moved is removed again.",
            "\u{2022} [Add files\u{2026}] / [Add folder\u{2026}] / [Remove selected]: the whole container is re-encrypted under a new key, every entry verified (SHA3-512), and only then replaced atomically.",
            "\u{2022} If another Shield window is using the same container, Shield waits briefly and then reports 'used by another task'.",
        ],
    ),
    (
        "Security behaviour",
        &[
            "\u{2022} After the idle time, when minimized (setting) or when another window is activated (setting), the open container's list is wiped and closed.",
            "\u{2022} With capture protection on, this window is left out of screenshots, screen recording and screen sharing. A camera can still film the screen.",
            "\u{2022} File names drawn on screen may be copied inside the GUI library (egui); those copies cannot be wiped completely.",
            "\u{2022} Temporary folders left by a crash are reported at the next start and can be removed. A damaged record file offers a recovery scan.",
        ],
    ),
];

pub const ALGO_ROWS: Rows = &[
    ("File format", "Shield (.shd) - the format version is only inside the encrypted metadata; older formats are not supported"),
    ("Data encryption", "XChaCha20-Poly1305 (256-bit key, 192-bit nonce, 128-bit tag)"),
    ("Chunks", "64 KiB authenticated chunks \u{00B7} nonce = prefix 15 B + type 1 B + counter 8 B \u{00B7} last-chunk flag detects truncation"),
    ("Key derivation", "Argon2id v1.3 \u{00B7} 256 MiB \u{00B7} 4 lanes \u{00B7} 3 + PIM passes (PIM 0-64, default 12)"),
    ("Key slots", "2 of 88 bytes \u{00B7} salt 16 B + nonce 24 B + wrapped DEK 32 B + tag 16 B \u{00B7} the unused slot is random"),
    ("Metadata", "Fixed size, encrypted and authenticated: format version, algorithm IDs, compression, lengths, file and folder counts, unpacked size, original name"),
    ("Hashes", "SHA3-512 - key file digests, restore verification, random pool \u{00B7} SHAKE256 - key-grade random output"),
    ("Compression", "LZMA2 or Zstandard inside a 7z container \u{00B7} already compressed files are stored"),
    ("Length hiding", "Random padding: 0 to clamp(length/16, 64 KiB, 1 GiB)"),
    ("Key files", "SHA3-512 digests (several are sorted and combined) \u{00B7} generated size 1-1024 KiB \u{00B7} owner-only from creation"),
    ("Passwords", "Unicode NFC normalization \u{00B7} at most 256 bytes (longer is refused) \u{00B7} constant-time comparison"),
    ("Randomness", "The OS CSPRNG is always the base (failure stops the task) \u{00B7} timers, jitter, system statistics, mouse etc. are only mixed into a SHA3-512 pool \u{00B7} SHAKE256 output"),
    ("Temporary data", "SecTemp: blocks encrypted under a new key per task (index and counter authenticated), deleted afterwards"),
    ("Concurrent use", "Inter-process lock per container (Windows LockFileEx, Linux flock): writing exclusive, reading shared"),
    ("Settings protection", "Security settings locked by the settings password: Argon2id 128 MiB \u{00B7} HMAC-SHA3-512 detects edits of the settings file"),
    ("Update signatures", "OpenPGP detached signatures (rPGP) \u{00B7} built-in public key \u{00B7} SHA-256 from a signed manifest \u{00B7} HTTPS (rustls)"),
];

pub const ALGO_NOTES: &[&str] = &[
    "\u{2022} The 4 Argon2id lanes are part of the format, but the library used (argon2 0.5) computes them one after another in one thread. The strength is the same.",
    "\u{2022} Zstandard only takes a level, and compresses in one thread.",
    "\u{2022} The size of the encrypted file reveals the rough size of the original; padding only hides it within that range.",
    "\u{2022} Malware running as the same user, administrator programs and kernel-level attacks cannot be stopped.",
    "\u{2022} The strength meter is a rough estimate that knows common patterns; it does not guarantee any attack cost.",
];
