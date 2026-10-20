/*
  Purple Loop: YARA rules for credential exposure on disk.

  These rules find secrets that should never sit in a file share, repository, home
  directory or build artifact: cloud service account keys, private keys, Terraform state
  with secrets, and cloud credential files. Attackers who gain any foothold search for
  exactly these files (ATT&CK T1552 Unsecured Credentials), so defenders should find
  them first.

  Each rule requires several structural markers, not a single keyword, so documentation
  that merely mentions a key format does not match.

  Tests: tests/test_yara_rules.py builds obviously fake positive samples at runtime and
  checks every rule against the benign corpus in tests/yara_samples/benign/.
*/

rule gcp_service_account_key_file
{
    meta:
        description = "Google Cloud service account key file (JSON). Grants API access as the service account until the key is deleted."
        author = "Aryan Dhuru"
        date = "2026-10-15"
        severity = "high"
        mitre_attack_id = "T1552.001"
        reference = "https://cloud.google.com/iam/docs/keys-create-delete"
        false_positives = "Intentional key files in a secrets manager export or a locked-down CI secret store."

    strings:
        $type     = /"type"\s*:\s*"service_account"/
        $key_id   = "\"private_key_id\""
        $key      = "\"private_key\""
        $email    = /"client_email"\s*:\s*"[^"]+\.iam\.gserviceaccount\.com"/

    condition:
        // Key files are ~2.3 KB; the size cap keeps large JSON exports from matching on stray fields.
        filesize < 20KB and all of them
}

rule pem_private_key
{
    meta:
        description = "PEM-encoded private key (PKCS#8, RSA, EC, DSA or OpenSSH) with both header and footer present."
        author = "Aryan Dhuru"
        date = "2026-10-15"
        severity = "high"
        mitre_attack_id = "T1552.004"
        reference = "https://datatracker.ietf.org/doc/html/rfc7468"
        false_positives = "Test fixtures in third-party packages; documentation that embeds a complete example key."

    strings:
        $begin_pkcs8   = "-----BEGIN PRIVATE KEY-----"
        $begin_enc     = "-----BEGIN ENCRYPTED PRIVATE KEY-----"
        $begin_rsa     = "-----BEGIN RSA PRIVATE KEY-----"
        $begin_ec      = "-----BEGIN EC PRIVATE KEY-----"
        $begin_dsa     = "-----BEGIN DSA PRIVATE KEY-----"
        $begin_openssh = "-----BEGIN OPENSSH PRIVATE KEY-----"

        $end_pkcs8     = "-----END PRIVATE KEY-----"
        $end_enc       = "-----END ENCRYPTED PRIVATE KEY-----"
        $end_rsa       = "-----END RSA PRIVATE KEY-----"
        $end_ec        = "-----END EC PRIVATE KEY-----"
        $end_dsa       = "-----END DSA PRIVATE KEY-----"
        $end_openssh   = "-----END OPENSSH PRIVATE KEY-----"

    condition:
        // Header alone is common in docs ("paste your -----BEGIN PRIVATE KEY----- here");
        // a real key has a footer too. Public keys and certificates use different labels.
        any of ($begin_*) and any of ($end_*)
}

rule terraform_state_with_secrets
{
    meta:
        description = "Terraform state file containing a populated secret attribute. State stores resource attributes in plain text, including passwords and keys."
        author = "Aryan Dhuru"
        date = "2026-10-15"
        severity = "high"
        mitre_attack_id = "T1552.001"
        reference = "https://developer.hashicorp.com/terraform/language/state/sensitive-data"
        false_positives = "State files kept in an encrypted, access-controlled backend are expected to contain secrets; this rule targets copies on disk."

    strings:
        // Markers present in every Terraform state file (format version 4).
        $tf_version = "\"terraform_version\""
        $lineage    = "\"lineage\""
        $resources  = "\"resources\""

        // A secret-looking attribute with a non-empty value of 8+ characters.
        $secret_attr = /"(password|admin_password|master_password|private_key|private_key_pem|client_secret|secret|secret_key|access_key|token)"\s*:\s*"[^"]{8,}"/

        // Not a secret: Secret Manager resources store the secret's resource NAME in an
        // attribute called "secret" ("projects/p/secrets/name"). Found on the lab's own
        // state, which holds no secret values (passwords are write-only arguments).
        $secret_ref = /"secret"\s*:\s*"projects\/[^"\/]+\/secrets\/[^"]+"/

    condition:
        // Every $secret_ref also matches $secret_attr, so require a match that isn't one.
        all of ($tf_version, $lineage, $resources) and #secret_attr > #secret_ref
}

rule cloud_credential_file
{
    meta:
        description = "Cloud credential material: gcloud user application-default credentials, an AWS credentials file with a secret key, or a Google API key."
        author = "Aryan Dhuru"
        date = "2026-10-15"
        severity = "medium"
        mitre_attack_id = "T1552.001"
        reference = "https://cloud.google.com/docs/authentication/application-default-credentials"
        false_positives = "A developer's own credential file in its default location (e.g. %APPDATA%\\gcloud); scope scans to shares, repositories and build output."

    strings:
        // gcloud auth application-default login writes this file (user credentials, long-lived refresh token).
        $adc_type      = /"type"\s*:\s*"authorized_user"/
        $refresh_token = "\"refresh_token\""
        $client_secret = "\"client_secret\""

        // ~/.aws/credentials: secret access keys are 40 characters.
        $aws_secret    = /aws_secret_access_key\s*=\s*[A-Za-z0-9\/+=]{40}/

        // Google API keys: "AIza" followed by 35 URL-safe characters.
        $google_api_key = /AIza[0-9A-Za-z_\-]{35}/

    condition:
        ($adc_type and $refresh_token and $client_secret) or $aws_secret or $google_api_key
}
