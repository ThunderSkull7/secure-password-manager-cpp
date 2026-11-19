# Vault Backup and Recovery

The vault is an encrypted file, but a backup still contains sensitive credential data. Protect backup copies accordingly. This guide describes a manual file-copy workflow; the application does not currently schedule backups or provide a recovery key.

## Back up a saved vault

1. Save the vault in the application and exit it cleanly.
2. Copy the vault file from the path supplied when starting the application to a separate, access-controlled storage device.
3. Keep more than one dated copy if you need recovery from accidental overwrite or file corruption.
4. Confirm that each copy has the expected size and can be copied back to a temporary test location. Do not replace the live vault during this check.

Do not put the master password in the backup filename, directory name, or same backup folder. Do not commit vault files to Git or upload them to an untrusted file-sharing service. A separate device is preferable to another folder on the same disk.

## Restore a copy

1. Exit the application.
2. Preserve the current vault under a different filename.
3. Copy the chosen backup to the path expected by the application.
4. Unlock the restored copy with the original master password.

A backup does not make a forgotten master password recoverable. The password-derived key protects the vault; there is no password reset service or recovery key. If a copy is corrupted or the password is lost, try another known-good backup. Keep the original file until the restored copy has been opened and checked.

This manual procedure does not establish backup encryption at the storage-device level, automatic retention, or a tested disaster-recovery service. Evaluate those requirements before storing vaults on shared or cloud-synced devices.
