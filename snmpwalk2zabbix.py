#!/usr/bin/env python3
# Copyright Sean Bradley 2022
# Copyright Jojangers 2023
# Repository https://github.com/Jojangers/SNMPWALK2ZABBIX
#
# LICENSE https://github.com/Jojangers/SNMPWALK2ZABBIX/blob/main/LICENSE
#
# SNMPWALK2ZABBIX : Create a Zabbix template from an SNMPWALK response.
# Copyright (C) 2022 Sean Bradley
# Copyright (C) 2023 Jojangers
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import os
import re
import uuid


###########
# LOGGING #
###########
# TODO: add to function.

def setup_logger(loglevel):
    logformatter = logging.Formatter('%(asctime)s %(levelname)s [%(name)s] %(message)s')
    filehandler = logging.FileHandler("debug/debug.log")
    filehandler.setFormatter(logformatter)
    consolehandler = logging.StreamHandler()
    consolehandler.setFormatter(logformatter)
    loglevel = loglevel.upper()
    rootlogger = logging.getLogger(__name__)
    rootlogger.addHandler(filehandler)
    rootlogger.addHandler(consolehandler)
    rootlogger.setLevel(loglevel)
    return rootlogger

############
# ARGPARSE #
############

def setup_arguments():
    parser = argparse.ArgumentParser(description="python script for making zabbix template from snmpwalk output.")
    parser.add_argument("-c", "--community", default="public", type=str, help="snmp v2c community string")
    parser.add_argument("host", help="hostname or ip address to perform snmpwalk on", type=str)
    parser.add_argument("oid", default=".", help="base OID to perform snmpwalk on.", type=str)
    parser.add_argument("-o", "--output", default="template.xml", help="destination filename")
    args = parser.parse_args()
    return args



#########
# CLASS #
#########

class snmpwalk2zabbix():
    def __init__(self):
        import logging
        """
        instance containing the data for creating a full template
        

        Args:
            host (_type_): _description_
            community (_type_): _description_
        """
        # TODO: add snmpv3 support
        # replace community with version and use a seperate class function to set auth?
        #self.host = host
        #self.community = community
        self.logging = logging.getLogger(__name__)
        self.discovery_rules = {}
        self.items = []
        self.valuemaps = {}
        
    ###################
    # TEMPLATE EXPORT #
    ###################
    
    """
    # TODO: create function to upload to zabbix
    def upload_to_zabbix(self, template_name="template", zbx_api_url, zbx_uname, zbx_api_token):
        import zapi
    """    
        
        
    def create_yaml_template_file(self, template_name="template", filename="template.yaml"):
        
        try:
            import yaml
        except ImportError:
            self.logging.error("you need to install yaml for python via pip install pyyaml")
            return
        # TODO: add options to add to host groups
        description = 'Template built by SNMPWALK2ZABBIX script from https://github.com/Jojangers/SNMPWALK2ZABBIX'
        export_dict = {"zabbix_export":{"version": '6.2',"templates": []}}
        template = {
            "uuid": uuid.uuid4().hex,
            "template": template_name,
            "name": template_name,
            "description": description,
            "groups": [{"name": "Templates"}],
            "discovery_rules": []
        }
        if len(self.items):
            template['items'] = self.items
            
        if len(self.discovery_rules):
            for i in self.discovery_rules:
                template['discovery_rules'].append(self.discovery_rules[i])
            
        if len(self.valuemaps):
            template['valuemaps'].append(self.valuemaps)
        
        export_dict["zabbix_export"]["templates"].append(template)
        # TODO: add filepath validation.
        # TODO: add check to ensure filename ends in ".yaml"
        with open(filename, 'w') as stream:
            yaml.dump(export_dict, stream)
        self.logging.info('finished writing template to: %s', filename)
            
        
            
    
    #################
    # TEMPLATE READ #
    #################

    def cli_walk_from_oid(self, host, base_oid, community="public"):
        """
        performs snmpwalk on the specified oid and adds any oids found
        to the instance.

        Args:
            base_oid (str): base oid to query with snmpwalk.
        """
        oid_list = self.__get_oid_list_from_snmpwalk(host, community, base_oid)
        for i, oid in enumerate(oid_list):
            self.logging.debug("processing OID=%s", oid)
            
            oid_kvp = self.__get_oid_kvp(oid)
            if oid_kvp is not None:
                self.logging.debug(f"oid string: {oid_kvp[0]}, zabbix datatype: {oid_kvp[1]}, oid value: {oid_kvp[2]}")
                oid_dict = self.__parse_oidstring(oid_kvp[0])
                # create item prototype
                if oid_dict["IsTable"]:
                    self.__add_discovery(oid_dict, oid_kvp[1])
                # create normal item
                elif not oid_dict["IsTable"]:
                    self.__add_item(oid_dict, oid_kvp[1])
        return oid_list
    """
    def read_from_file(self, filename):
        # TODO: add function to read snmpwalk from filename
    """
    
    """
    def read_from_mib(self, mibpath, baseoid):
        # TODO: add function to read and parse mib file directly.
    """
    
            
    ######################
    # INTERNAL FUNCTIONS #
    ######################
    
    def __add_item(self, oid_dict, data_type="NUMERIC"):
        # TODO: add default values for refresh delay.
        name = oid_dict["Name"]
        description = oid_dict["Description"]
        key = oid_dict["Key"]
        oid = oid_dict["Full_oid"]
        
        item = {"name": name, 
                "uuid": uuid.uuid4().hex,
                "type": "SNMP_AGENT",
                "snmp_oid": oid,
                "key": key,
                "status": "DISABLED",
                "value_type": data_type,
                "description": description
                }
        self.items.append(item)
        self.logging.info(f"ITEM -> {name} -> {data_type}")
        return item
        
    def __add_discovery(self, oid_dict, data_type="NUMERIC"):
        # just to make code more readable.
        end_oid = oid_dict["end_oid"]
        key = oid_dict["Key"]
        trimmed_oid = oid_dict["Trimmed_oid"]
        discovery_name = oid_dict["Discovery_rule"]
        prototype_name = oid_dict["Name"]
        description = oid_dict["Description"]
        
        if not discovery_name in self.discovery_rules:
            # add discovery rule
            Full_oid = oid_dict["Full_oid"]
            self.discovery_rules[discovery_name] = {"type": "SNMP_AGENT",
                                                    "status": "DISABLED",
                                                    "name": discovery_name,
                                                    "uuid": uuid.uuid4().hex,
                                                    "key": key,
                                                    "snmp_oid": Full_oid,
                                                    "item_prototypes": []
                }
            self.logging.debug("discovery rule: %s", self.discovery_rules[discovery_name])
            self.current_item = ""
            
        if end_oid != self.current_item:
            # append prototype items.
            self.current_item = end_oid
            #item_prototype = [end_oid, mib, key, trimmed_oid, data_type, description]
            item_prototype = {"name": prototype_name + """.[{#SNMPINDEX}]""",
                              "uuid": uuid.uuid4().hex,
                              "type": "SNMP_AGENT",
                              "status": "DISABLED",
                              "snmp_oid": trimmed_oid + """.{#SNMPINDEX}""",
                              "key": key + """.{#SNMPINDEX}""",
                              "description": description
                              }
            self.logging.debug("item prototype: %s", item_prototype)
            self.discovery_rules[discovery_name]["item_prototypes"].append(item_prototype)
            self.logging.info(f"Item prototype -> {prototype_name} -> {end_oid} ({data_type}) ")
            return item_prototype
        else:
            self.logging.debug("item already added, skipping: %s", end_oid)
            return
        

    """
    def __add_valuemaps(self):
        name = "something"
        mappings = "something2"
        # TODO: add reading and adding of valuemaps from mib. 
        self.logging.error("Valuemap function not added yet.") 
        valuemap = {"name" : "<++>",
                    "uuid" : uuid.uuid4().hex,
                    "mappings" : {} 
            }
    """
        
    def __get_oid_list_from_snmpwalk(self, host, community, base_oid):
        """
        runs snmpwalk on self.host, splits the result and returns a list.

        Args:
            host (str): ip or hostname of the target host.
            community (str): snmpv2 community string.
            base_oid (str): string containing the base oid to parse with snmpwalk

        Returns:
            OID_LIST: list of the OIDs and their values.
        """        
        self.logging.info("running snmpwalk")
        # TODO: add more error checking
        # - if response is a valid list of oids
        # - is hostname reachable on community?
        response = os.popen('snmpwalk -v 2c -On -c ' +community + ' ' + host + ' ' + base_oid).read()
        self.logging.debug("got response: %s", response)
        OID_LIST = response.split("\n")
        self.logging.info("Processing %s rows", str(len(OID_LIST)))
        return OID_LIST

        
    
    @staticmethod
    def __parse_oidstring(oidstring):
        oid_dict = {}
        """
        translates the oid string and returns a dictionary
        containing the mibstring, item description and full oid path.

        Args:
            oidstring (string): full numerical oid path

        Returns:
            oid_dict: dictionary containing the info
                MIB (str): mibstring (last part of the mib path)
                Description (str): Description of the oid value
                fullOidStringParts (list): full oid path in parts.
                Discovery (Bool): True if OID is in a table.
        """        
        # TODO: add checking to see if this succeds.
        # TODO: find better way to do this without os.popen
        fullOidString = os.popen('snmptranslate -Of ' + oidstring).read().strip()
        description = os.popen('snmptranslate -Td ' + oidstring).read()
        mibstring = os.popen('snmptranslate -Tz ' + oidstring).read()
        mib = mibstring.strip()
        # remove the last identifier on the oid string.
        trimmed_oid = oidstring.split(".")[:-1]
        trimmed_oid = ".".join(trimmed_oid)
        
        # TODO: add better error checking
        # TODO: validate description is actually translate.
        if description is not None:
            groups = re.search(r'DESCRIPTION.*("[^"]*")', description)
            if groups.group(1) is not None:
                description = groups.group(1)
                description = description.replace('"', '')
                description = description.replace('\\n', '&#13;')
                description = description.replace('<', '&lt;')
                description = description.replace('>', '&gt;')
                Description = re.sub(r"\s\s+", " ", description)

        
        if fullOidString is not None:
            fullOidStringParts = fullOidString.split(".")
            # remove the last id part of the OID
            # TODO: add support for ipv4 oid identifiers.
            if fullOidStringParts[-1].isdigit():
                fullOidStringParts.pop(-1)
            if fullOidStringParts[-3].upper().endswith("TABLE"):
                IsTable = True
                Discovery_rule = fullOidStringParts[-3]
            else:
                IsTable = False
                Discovery_rule = None
            
            Name = mib.split("::")[1]
            Name = Name.split(".")[0]
            
            key = mib.split(".")[:-1]
            key = ".".join(key)
            key = key.replace("::", ".")
            

        end_oid = fullOidStringParts[-1]
            
        oid_dict = {
            "Name" : Name,
            "IsTable": IsTable,
            "Description" : Description,
            "Key" : key,
            "end_oid": end_oid,
            "fullOidStringParts" : fullOidStringParts,
            "Trimmed_oid" : trimmed_oid,
            "Full_oid" : oidstring,
            "Discovery_rule": Discovery_rule
        }
        return oid_dict


    @staticmethod
    def __get_oid_kvp(snmpwalk_row):
        """
        checks the snmpwalk response row and returns ordered array
        containing the oid string, zabbix item datatype and the
        result value.

        Args:
            oid (str): full snmpwalk response row.

        Returns:
            oid_kvp: array split into oid string and oid result value.
                [0] = oid string
                [1] = zabbix item datatype
                [2] = result value (previously named "value")
        """
        zabbix_datatypes = {
            "DEFAULT": "TEXT",
            "STRING": "CHAR",
            "OID": "CHAR",
            "TIMETICKS": "UNSIGNED",
            "BITS": "TEXT",
            "COUNTER": "UNSIGNED",
            "COUNTER32": "UNSIGNED",
            "COUNTER64": "UNSIGNED",
            "GAUGE": "UNSIGNED",
            "GAUGE32": "UNSIGNED",
            "INTEGER": "FLOAT",
            "INTEGER32": "FLOAT",
            "IPADDR": "TEXT",
            "IPADDRESS": "TEXT",
            "NETADDDR": "TEXT",
            "NOTIF": "",  # SNMP Trap
            "TRAP": "",  # SNMP Trap
            "OBJECTID": "TEXT",
            "OCTETSTR": "TEXT",
            "OPAQUE": "TEXT",
            "TICKS": "UNSIGNED",
            "UNSIGNED32": "UNSIGNED",
            "WRONG TYPE (SHOULD BE GAUGE32 OR UNSIGNED32)": "TEXT",
            "\"\"": "TEXT",
            "HEX-STRING": "TEXT",
        }
        
        if len(snmpwalk_row) > 0 and not "NO MORE VARIABLES LEFT" in snmpwalk_row.upper():
            oid_kvp = snmpwalk_row.split("=")
            oid_kvp[0] = oid_kvp[0].strip()
            kvp_split = oid_kvp[1].split(":")
            if kvp_split[0]:
                zabbix_datatype = kvp_split[0].strip().upper()
            if kvp_split[1]:
                oid_kvp.append(kvp_split[1].strip())
            
            
            # self.mib = oid_kvp
            if zabbix_datatype in zabbix_datatypes:
                oid_kvp[1] = zabbix_datatypes[zabbix_datatype]
                
                # TODO: handle traps
                if zabbix_datatype == "NOTIF" or zabbix_datatype == "TRAP":
                    oid_kvp[1] = zabbix_datatypes["DEFAULT"]
                
            else:
                oid_kvp[1] = zabbix_datatypes["DEFAULT"]
            
            return oid_kvp
            # oid_kvp[0] = oid string
            # oid_kvp[1] = zabbix interface value
            # oid_kvp[2] = oid value
        else:
            return None
    
##########
# SCRIPT #
##########
def main(args, logger):
    snmptemplate = snmpwalk2zabbix()
    #snmptemplate.cli_walk_from_oid(host=args.host, community=args.community, base_oid=args.oid)
    snmptemplate.pysnmp_walk_from_oid(host=args.host, community=args.community, base_oid=args.oid)
    snmptemplate.create_yaml_template_file(filename="template.yaml")


if __name__ == "__main__":
    import logging
    import argparse
    # setup args and logger if run as a script.
    loglevel = "info"
    args = setup_arguments()
    logger = setup_logger(loglevel)
    main(args, logger)