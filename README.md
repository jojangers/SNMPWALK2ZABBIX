# SNMPWALK2ZABBIX

Create a Zabbix template from an SNMPWALK response.
created from code found at https://github.com/Sean-Bradley/SNMPWALK2ZABBIX
Changes can be found at the bottom of the README. 

> **NOTE** that this script will **NOT** automatically create a fully featured all bells and whistles perfect template exactly for your needs. It blindly reads the `snmpwalk` response and tries to create items and discovery rules from what ever it gets back. You will need to edit the result to make it exactly whatever you need it to be. The script comes with no support or warranty. Read the [license](LICENSE).

## Requirements

- Linux (Tested on Debian 11, RHEL 8 and Ubuntu 20.04)
- Python3 (use `python3 -V` to check)
- SNMP (uses SNMPv2 to query)
- SNMP-MIBS-Downloader, plus any other custom or proprietary MIBs you may want to use. It will use the MIB descriptions of OIDs as it generates the templates items and discovery rules.
- A working SNMP device that responds to an `snmpwalk` command
- Final template is **Zabbix 6 LTS** compatible

## Download

```bash
wget https://raw.githubusercontent.com/Jojangers/SNMPWALK2ZABBIX/master/snmpwalk2zabbix.py
```

## Install SNMP and SNMP-MIBS-Downloader

The server where you will run the script from, needs the SNMP tools and MIBs. You can get a good set of common MIBs when installing `snmp-mibs-downloader` on Debian/Ubuntu.

```bash
sudo apt update
sudo apt install snmp snmp-mibs-downloader
```

## Usage

```bash
python3 snmpwalk2zabbix.py -c community-string IP-address root-OID
```

- `community-string` : This is the v2c community name. Most systems default to use `public` as the community name.
- `IP-address` : The IP address of the SNMP device that returns a valid `snmpwalk` response.
- `root-OID` : Indicates which OID to start creating items from. An OID very low, e.g, `1`, will result in a much larger template, versus using `1.3` or `1.3.6` or `1.3.6.1` or `1.3.6.1.2` or `1.3.6.1.2.1`, etc.

## Example

Before using, ensure that you can at least do a simple `snmpwalk` from the server that you are running this script from.

E.g., I can `snmpwalk` my network router, and it responds.

```bash
snmpwalk -v 2c -c public 192.168.1.1 1.3.6.1.2.1
```

Example output

```
SNMPv2-MIB::sysDescr.0 = STRING: 1.2.0 0.9.1 v0001.0 Build 201203 Rel.59032n
SNMPv2-MIB::sysObjectID.0 = OID: SNMPv2-SMI::enterprises.16972
DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (292015000) 33 days, 19:09:10.00
SNMPv2-MIB::sysContact.0 = STRING: unknown
SNMPv2-MIB::sysName.0 = STRING: Archer MR600
SNMPv2-MIB::sysLocation.0 = STRING: unknown
... and many more lines
```

Now to generate the template.

```bash
python3 snmpwalk2zabbix.py -c public 192.168.1.1 1.3.6.1.2.1
```

It will try to produce a Zabbix 6 LTS compatible YAML template that you can import.

E.g.,

The YAML file will be saved into the same folder as where the script was run. It named my example output file as `template.yaml`

Download/Copy/SFTP the saved YAML file to a location onto your local computer where you can then import it into the Zabbix UI `Configuration-->Templates-->[Import]`.


Note that the generated template is not perfect. It is up to you if you want to make it better. The items and discovery rules are created as **DISABLED** by default. This is to minimize the possibility that assigning this template to a host won't overload your Zabbix server/proxy or your SNMP host/device.

After importing the template, you should review which items and discovery rules that you want enabled. If a MIB description can be found for an OID, then it will use it in the name and description of the item and discovery rule. And hopefully that will make the process of deciding if you want it enabled or not, a little easier.

When you assign your new template to a host in Zabbix. Make sure that your Zabbix server, or Zabbix proxy (if monitored by proxy) can also access your SNMP host/device.

Also note that despite the creation of the template requiring SNMPv2, you can actually still use the resulting template with an SNMPv3 configured host provided that you've configured your host correctly in Zabbix to use SNMPv3.

I say again. This script will NOT automatically create a fully featured all bells and whistles perfect template exactly for all your needs. The resulting template may be very large and contain many useless items and discovery rules. You will need to edit the result to make it exactly whatever you want it to be. This script comes with no warranty. Don't forget to read the [license](LICENSE).

## CHANGES

- refactored the script to a class and methods
- changed the output format to YAML
- changed multiple hardcoded functions to be more dynamic
- added better logging with the python logging module.
- planning to add more functionality in the future.

