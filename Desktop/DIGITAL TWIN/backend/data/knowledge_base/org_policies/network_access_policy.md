# ACME Network Access Policy

Sample policy shipped with the Cyber Digital Twin. Replace it with your organisation's own text.

## Wired and wireless access control

Every switch port and wireless network that reaches the corporate VLAN must authenticate the connecting device with 802.1X. MAC authentication bypass is permitted only for devices that cannot run a supplicant, such as printers, and each exception must be recorded with an owner and a review date. A device that fails authentication is placed in the guest VLAN. This limits network boundary bridging (T1599) from guest or unmanaged devices.

## Layer 2 protection on access switches

All access switches must enable DHCP snooping, dynamic ARP inspection and port security with a limit of two MAC addresses per port. These settings stop ARP cache poisoning (T1557.002) and MAC flooding on the local segment. A switch that cannot support dynamic ARP inspection must not carry user VLANs.

## Segmentation between zones

Traffic between the guest, corporate, server and management zones must pass a firewall with a default deny rule. Guest devices may reach the internet only. Access from the corporate zone to the server zone is limited to the ports each business application needs. Rules are reviewed every six months and unused rules are removed.

## Monitoring of internal traffic

Network intrusion detection sensors must cover every zone that holds confidential or restricted data, and should cover the corporate zone. Sensors must load signatures for ARP anomalies, SMB lateral movement (T1021.002) and service scanning (T1046). Alerts are forwarded to the SIEM.
