# ACME Remote Access and Identity Policy

Sample policy shipped with the Cyber Digital Twin. Replace it with your organisation's own text.

## Multi-factor authentication

Multi-factor authentication is mandatory for every remote access service, including the VPN gateway, webmail and any administration portal reachable from the internet. A service that cannot enforce a second factor must not be exposed externally. This is the primary defence against use of external remote services (T1133) and stolen valid accounts (T1078).

## Account lockout and passwords

Accounts must lock for at least fifteen minutes after ten failed sign-in attempts within ten minutes, to slow brute force attacks (T1110). Passwords must be at least fourteen characters. Service accounts use generated secrets that are rotated every ninety days.

## Endpoint protection on servers

Endpoint detection and response agents must run in blocking mode on every workstation and on every server that stores confidential or restricted data, including file servers and database servers. This addresses credential dumping (T1003) and data encryption for impact (T1486).

## Backups

Systems that hold confidential or restricted data must have at least one offline or immutable backup copy, and a restore must be tested every quarter. Backups that are reachable from the production network do not count as offline.

## Data leaving the network

Outbound transfers of confidential or restricted data must be inspected by a data loss prevention control. Uploads to unapproved destinations are blocked, to limit exfiltration over alternative protocols (T1048).
