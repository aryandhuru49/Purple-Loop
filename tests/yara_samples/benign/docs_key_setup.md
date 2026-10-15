# Configuring the signing key

Store the key in Secret Manager, never in the repository. The value starts with a line
such as `-----BEGIN PRIVATE KEY-----`; paste the whole value into the secret, then delete
the local copy. Public certificates (`-----BEGIN CERTIFICATE-----`) are safe to commit.
