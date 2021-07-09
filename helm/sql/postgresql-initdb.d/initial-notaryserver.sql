CREATE DATABASE notaryserver;
CREATE USER {{ .Values.server.storageCredentials.user }} WITH PASSWORD '%% .Env.SERVERPASSWORD %%';
GRANT ALL PRIVILEGES ON DATABASE notaryserver TO {{ .Values.server.storageCredentials.user }};
