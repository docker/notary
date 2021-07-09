CREATE DATABASE IF NOT EXISTS `notarysigner`;

CREATE USER "{{ .Values.signer.storageCredentials.user }}"@"%" IDENTIFIED BY "%% .Env.SIGNERPASSWORD %%";

GRANT
	ALL PRIVILEGES ON `notarysigner`.* 
	TO "{{ .Values.signer.storageCredentials.user }}"@"%";
