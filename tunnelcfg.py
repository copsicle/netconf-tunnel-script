from configparser import ConfigParser as conf
from ncclient import manager as ncm
from ncclient.operations.rpc import RPCError
from sys import argv
from os.path import isfile
from xml.dom.minidom import parseString as xmlparse
from lxml.etree import tostring, XMLSyntaxError
from secrets import token_urlsafe as secret

import xmltemplates as xmlt

def get_config_file():
    argc = len(argv)
    cfgfile = ""
    if argc > 1:
        if isfile(argv[1]):
            cfgfile = argv[1]
        else:
            print("File argument not found.")
    assert isfile(cfgfile)
    parser = conf()
    assert parser.read(cfgfile)
    return parser

def connect_to_router(cfgfile, section):
    return ncm.connect(
        host=cfgfile[section]['host'],
        port=int(cfgfile[section]['port']),
        username=cfgfile[section]['user'],
        password=cfgfile[section]['pass'],
        hostkey_verify=cfgfile.getboolean(section, 'verify')
    )

def get_router_config(router, filter=None):
    if filter is not None:
        return router.get_config(source="running", filter=filter)
    return router.get_config(source="running")

def set_router_config(router, cfg):
    with router.locked('running'):
        result = router.edit_config(target="running", config=cfg)
    return result

def prettify_config(data):
    return xmlparse(data).toprettyxml()

def response_to_file(data, filename="response.xml", mode="w"):
    resfile = open(filename, mode)
    resfile.writelines(data)
    resfile.close()

def get_all_tag_values(data, tag):
    return [e.firstChild.nodeValue for e in data.getElementsByTagName(tag)]

def get_parent_by_tag(data, tag, value):
    for element in data.getElementsByTagName(tag):
        if element.firstChild.nodeValue == value:
            return element.parentNode
    raise Exception(f"Could not find element with tag {tag} and value {value}")

def get_first_available_number(arr, max=8):
    for i in range(max):
        if not str(i) in arr:
            return i
    raise Exception(f"Could not find valid tunnel ID out of maximum {max}")

def verify_element(element, tags):
    for i in tags.keys():
        val = tags[i]
        subel = element.getElementsByTagName(i)
        if subel:
            if isinstance(val, dict):
                verify_element(subel[0], val)
                continue
            elif subel[0].firstChild.nodeValue == val:
                continue
        raise Exception(f"Could not verify element {element.nodeName} with tag {i} and value {val}")
    return True

def find_element(router, cfgfile, filter, section, id, validation):
    res = xmlparse(get_router_config(router, filter).data_xml)
    elements = get_all_tag_values(res, id)
    elementname = cfgfile[section][id]
    if elements and elementname in elements:
        return verify_element(get_parent_by_tag(res, id, elementname), validation)
    return False

def check_existing_config(router, cfgfile, valid):
    if find_element(router, cfgfile, xmlt.trset_filter, 'trset', 'tag', valid['trset_validation']):
        print(f"Transform set already exists, not creating a new one")
    else:
        print("Creating transform set")
        set_router_config(router, xmlt.ipsec_trset_config.format(
            cfgfile['trset']['tag'],
            cfgfile['trset']['esp'],
            cfgfile['trset']['key-bit']
        ))
    if find_element(router, cfgfile, xmlt.profile_filter, 'profile', 'name', valid['profile_validation']):
        print(f"IPsec profile already exists, not creating a new one")
    else:
        print("Creating IPsec profile")
        set_router_config(router, xmlt.ipsec_profile_config.format(
            cfgfile['profile']['name'],
            cfgfile['profile']['group'],
            cfgfile['trset']['tag']
        ))
    if find_element(router, cfgfile, xmlt.policy_filter, 'policy', 'number', valid['policy_validation']):
        print("ISAKMP policy already exists, not creating a new one")
    else:
        print("Creating ISAKMP policy")
        set_router_config(router, xmlt.isakmp_policy_config.format(
            cfgfile['policy']['number'],
            cfgfile['policy']['authentication'],
            cfgfile['policy']['encryption'],
            cfgfile['policy']['key'],
            cfgfile['policy']['encryption'],
            cfgfile['policy']['group'],
            cfgfile['policy']['hash'],
            cfgfile['policy']['lifetime']
        ))

def get_interface_address(router, cfgfile, section):
    inttype = cfgfile[section]['inttype']
    intname = cfgfile[section]['intname']
    res = get_router_config(router, xmlt.interface_address_filter.format(
        inttype, intname, inttype))
    xmlres = xmlparse(res.data_xml).getElementsByTagName('address')
    if len(xmlres) < 2:
        raise Exception(f"Could not get IP from {section} interface {inttype} {intname}")
    ip = xmlres[1].firstChild.nodeValue
    print(f"Got IP {ip} from {section} interface {inttype} {intname}")
    return ip

def get_vacant_tunnel(router):
    tunnels = xmlparse(get_router_config(router, xmlt.tunnel_filter).data_xml)
    tags = get_all_tag_values(tunnels, 'name')
    tunid = get_first_available_number(tags)
    print(f"Found available tunnel id - {tunid}")
    return tunid

def get_router(cfgfile, section):
    site = connect_to_router(cfgfile, section)
    assert site.connected
    return site

def get_hostname(router):
    res = xmlparse(get_router_config(router, xmlt.hostname_filter).data_xml)
    return res.getElementsByTagName('hostname')[0].firstChild.nodeValue

def get_router_info(router, cfgfile, section, valid):
    print(f"Checking configuration of site {section}")
    check_existing_config(router, cfgfile, valid)
    if cfgfile.getboolean('general', 'getipfromint'):
        ip = get_interface_address(router, cfgfile, section)
    else:
        ip = cfgfile[section]['host']
    assert ip
    tun_id = get_vacant_tunnel(router)
    name = get_hostname(router)
    return ip, tun_id, name

def get_int_from_ip(router, cfgfile, section):
    res = xmlparse(get_router_config(router, xmlt.interface_address_filter_xpath.format(cfgfile[section]['host'])).data_xml)
    inttype = res.getElementsByTagName('interface')[0].firstChild.nodeName
    intname = res.getElementsByTagName('name')[0].firstChild.nodeValue
    return inttype + intname


def get_tunnel_source(router, cfgfile, section, tunid):
    if cfgfile.getboolean('general', 'setintassrc'):
        if cfgfile.getboolean('general', 'getintfromip'):
            src = get_int_from_ip(router, cfgfile, section)
        else:
            src = cfgfile[section]['inttype'] + cfgfile[section]['intname']
    else:
        if cfgfile.getboolean('general', 'getipfromint'):
            src = get_interface_address(router, cfgfile, section)
        else:
            src = cfgfile[section]['host']
    return src

def validate_identical_tunnel(router, cfgfile, section, destip):
    res = xmlparse(get_router_config(router, xmlt.identical_tunnel_filter.format(
        destip,
        cfgfile['profile']['name']
    )).data_xml)
    name = res.getElementsByTagName('name')
    if len(name) > 0:
        tid = name[0].firstChild.nodeValue
        ip = res.getElementsByTagName('address') 
        if len(ip) > 1:
            if (ip[1].firstChild.nodeValue != cfgfile[section]['tunip'] or
            res.getElementsByTagName('mask')[0].firstChild.nodeValue != cfgfile[section]['tunmask']):
                print(f"Found an identical tunnel (Tunnel{tid}) with mismatching IP addressing, reconfiguring")
                return False, tid
        print(f"Found an identical tunnel at Tunnel{tid} on router {section}, skipping")
        return True, None
    return False, None

def check_key(router, cfgfile, destip):
    res = xmlparse(get_router_config(router, xmlt.isakmp_key_filter.format(destip)).data_xml)
    key = res.getElementsByTagName('key')
    if len(key) < 2:
        return None
    return key[1].firstChild.nodeValue

def override_key(router, cfgfile, destip, new_key, existing_key):
    if existing_key is not None:
        if new_key != existing_key:
            if cfgfile.getboolean('general', 'overridepsk'):
                print(f"Overriding key ({existing_key}) for destination {destip}")
                set_router_config(router, xmlt.isakmp_key_delete.format(
                    existing_key,
                    destip
                ))
            else:
                raise Exception("A mismatching key for destination {destip} exists and key overriding is disabled, exiting")
        else:
            print(f"Key {new_key} already exists for destination {destip}, not installing")

def verify_psk(r1, r2, cfgfile, r1sec, r2sec, r1ip, r2ip):
    if cfgfile.getboolean('general', 'generatepsk'):
        key = secret(cfgfile.getint('general', 'secretlength'))
        print(f"Generated key ({key}) for tunnel between {r1sec} and {r2sec}")
    else:
        if cfgfile[r1sec]['psk'] != cfgfile[r2sec]['psk']:
            raise Exception(f"Key configuration mismatch between {r1sec} and {r2sec}")
        key = cfgfile[r1sec]['psk']
    
    r1key = check_key(r1, cfgfile, r2ip)
    r2key = check_key(r2, cfgfile, r1ip)
    
    override_key(r1, cfgfile, r2ip, key, r1key)
    override_key(r2, cfgfile, r1ip, key, r2key)

    set_router_config(r1, xmlt.isakmp_key_config.format(key, r2ip))
    set_router_config(r2, xmlt.isakmp_key_config.format(key, r1ip))

def configure_tunnel(router, cfgfile, section, destip, destname, tunid, destid, tunkey):
    isident, overtunid = validate_identical_tunnel(router, cfgfile, section, destip)
    if isident:
        return
    elif overtunid is not None:
        tunid = overtunid
    print(f"Configuring tunnel {tunid} on {section} to {destname} at {destip}")
    set_router_config(router, xmlt.tunnel_config.format(
        tunid,
        destname,
        destid,
        cfgfile[section]['tunip'],
        cfgfile[section]['tunmask'],
        get_tunnel_source(router, cfgfile, section, tunid),
        destip,
        cfgfile['profile']['name']
    ))
    if cfgfile.getboolean('general', 'enableospf'):
        set_router_config(router, xmlt.ospf_proc_config.format(
            cfgfile[section]['ospfid'],
            tunid
        ))
        set_router_config(router, xmlt.ospf_int_config.format(
            tunid,
            cfgfile[section]['ospfid'],
            cfgfile[section]['ospfarea']
        ))

def verify_general_config(cfgfile):
    option_list = ["enableospf", "setintassrc", "getintfromip", "getipfromint", "generatepsk", "overridepsk", "secretlength"]

    for opt in option_list:
        if not cfgfile.has_option('general', opt):
            raise Exception(f"Could not verify option {opt} in the general section of the configuration file")

def verify_router_config(router, cfgfile):
    if not cfgfile.has_section(router):
        raise Exception(f"Could not find section {router} in configuration file")
    
    option_list = ["host", "port", "user", "pass", "verify", "tunip", "tunmask"]
    if ((cfgfile.getboolean('general', 'setintassrc') and not cfgfile.getboolean('general', 'getintfromip')) or
     (not cfgfile.getboolean('general', 'setintassrc') and cfgfile.getboolean('general', 'getipfromint'))):
        option_list.append("inttype")
        option_list.append("intname")
    
    if cfgfile.getboolean('general', 'enableospf'):
        option_list.append("ospfid")
        option_list.append("ospfarea")

    if not cfgfile.getboolean('general', 'generatepsk'):
        option_list.append("psk")

    for opt in option_list:
        if not cfgfile.has_option(router, opt):
            raise Exception(f"Could not verify option {opt} for section {router} in configuration file")
        

def get_validations(cfgfile):
    return {
            "trset_validation": {"esp": cfgfile['trset']['esp'], "key-bit": cfgfile['trset']['key-bit']},
            "profile_validation": {"set": {"pfs": {"group": cfgfile['profile']['group']},
                "transform-set": cfgfile['trset']['tag']}},
            "policy_validation": {"authentication": cfgfile['policy']['authentication'],
                "encryption": {cfgfile['policy']['encryption']: {"key": cfgfile['policy']['key']}},
                "group": cfgfile['policy']['group'],
                "hash": cfgfile['policy']['hash'],
                "lifetime": cfgfile['policy']['lifetime']}
            }
    
def tunnel_setup(cfgfile, validations, router1, router2):
    verify_router_config(router1, cfgfile)
    verify_router_config(router2, cfgfile)

    print(f"\nProcessing tunnel between {router1} and {router2}\n")
    router1_site = get_router(cfgfile, router1)
    router2_site = get_router(cfgfile, router2)

    router1_ip, router1_tun, router1_name = get_router_info(router1_site, cfgfile, router1, validations)
    router2_ip, router2_tun, router2_name = get_router_info(router2_site, cfgfile, router2, validations)

    key = verify_psk(router1_site, router2_site, cfgfile, router1, router2, router1_ip, router2_ip)

    configure_tunnel(router1_site, cfgfile, router1, router2_ip, router2_name, router1_tun, router2_tun, key)
    configure_tunnel(router2_site, cfgfile, router2, router1_ip, router1_name, router2_tun, router1_tun, key)

def loop_over_arguments(cfgfile, validations):
    argc = len(argv)
    if argc % 2 != 0 or argc < 4:
        print("Invalid amount of arguments, pairs of source - destination are required")
        exit(1)
    count = 2
    while count != argc:
        try:
            tunnel_setup(cfgfile, validations, argv[count], argv[count + 1])
        except RPCError as e:
            print(tostring(e.xml))
        except XMLSyntaxError as e:
            print(e)
        except Exception as e:
            print(e)
        finally:
            count += 2

if __name__ == "__main__":
    config = get_config_file()
    verify_general_config(config)
    loop_over_arguments(config, get_validations(config))
    exit(0)