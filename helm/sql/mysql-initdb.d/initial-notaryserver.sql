CREATE DATABASE IF NOT EXISTS `notaryserver`;

CREATE USER "{{ .Values.server.storageCredentials.user }}"@"%" IDENTIFIED BY "%% .Env.SERVERPASSWORD %%";

GRANT
	ALL PRIVILEGES ON `notaryserver`.* 
	TO "{{ .Values.server.storageCredentials.user }}"@"%";
