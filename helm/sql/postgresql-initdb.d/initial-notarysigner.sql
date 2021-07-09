CREATE DATABASE notarysigner;
CREATE USER {{ .Values.signer.storageCredentials.user }} WITH PASSWORD '%% .Env.SIGNERPASSWORD %%';
GRANT ALL PRIVILEGES ON DATABASE notarysigner TO {{ .Values.signer.storageCredentials.user }};
