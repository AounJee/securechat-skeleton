# Manual Testing Checklist

### 1. Certificate Exchange
- Capture Wireshark traffic (Hello → cert)
- Validate cert using CA

### 2. DH Key Exchange
- Confirm public values A, B shown in Wireshark

### 3. Login Phase
- Ensure AES-ECB encrypted password seen as ciphertext

### 4. Chat Messages
- Messages appear encrypted in Wireshark
- Server prints plaintext after decrypting

### 5. Transcript Log
- transcripts/session_x.log contains append-only lines
- transcript SHA-256 matches the end receipt

### 6. Evidence Screenshots
- GitHub commits
- Certificate files created
- Wireshark captures
- DB rows
