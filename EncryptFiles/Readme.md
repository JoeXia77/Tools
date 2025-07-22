#### Encrypt your file before upload it to cloud drive, used to prevent cloud disk identify/delete my file

## Reason: 
some cloud disk will automate scan the file fingerpringing, metadata or more. 

## Risk: 
Except leaks, it may delete my some of my files ...

## Method:
Used AES‑256‑GCM encryption with PBKDF2 key derivation and per-chunk random nonces.
This setup ensures that your files are encrypted securely, names and content are hidden, tampering is detectable, and even repeated data looks different—making it safe for cloud storage or backups.

## How to use:
set up path (like source_dir) and password.
then run (Uncomment) one of the following method at the bottom : encrypt_folder_items or decrypt_enc_folder
if need, pip install cryptography tqdm








