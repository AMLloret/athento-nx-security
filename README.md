# Athento Security for Nuxeo

## Requirements

- Bouncy castle lib 1.49+ (bcprov-jdk15on.jar)

### Properties

- _cipher.key_: it is a mandatory property used to encrypt the information.
- _password.lastmodification.date_: it is the default last modification date.
- _password.expiration.days_: it is the number of days to check expirated passwords.
- _password.oldpassword.days_: it is the number of days to check old passwords.

### Document security

- Apply athentosec security schema to apply access control with:
 * Principals
 * Signed tokens
 * IPs
 * Content xpath
