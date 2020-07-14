from gosnmp import *
import argparse
import configparser
import xml.etree.cElementTree as ET
import logging

DEBUGGPRINT = True

class Invent:
    def __init__(self):
        self.name = ""
        self.sn = ""

class Device:
    def __init__(self,ip):
        self.ipaddr = ip
        self.inventory = []

class Devices:
    def __init__(self):
        self.devlist = []


if __name__ == '__main__':
    stoidmodel = "1.3.6.1.4.1.37072.303.2.5.1.1.1.4.0"
    snoid = "1.3.6.1.2.1.47.1.1.1.1.11"
    sysnameoid = "1.3.6.1.4.1.37072.303.2.5.1.1.1.1.0"
    syslocationoid = "1.3.6.1.4.1.37072.303.2.5.1.1.1.2.0"
    sysdescroid = "1.3.6.1.4.1.37072.303.2.5.1.1.1.3.0"

    parcer = argparse.ArgumentParser(description="Params")
    parcer.add_argument('-f', type=str, help="File with devices IP addresses",required=True)
    parcer.add_argument('-v', type=int, help="SNMP protocol version, must be 2 for verion v2c or 3 for version 3",required=True)
    parcer.add_argument('-c', type=str, help="SNMP community - only for v2c")
    parcer.add_argument('-u', type=str, help="SNMPv3 user")
    parcer.add_argument('-a', type=str, help="Auth alghorithm, must be sha, md5 or none")
    parcer.add_argument('-A', type=str, help="Auth password")
    parcer.add_argument('-x', type=str, help="Priv alghorithm, must be aes128, aes192, aes256, des 3des or none")
    parcer.add_argument('-X', type=str, help="Priv password")
    parcer.add_argument('-o',type=str, help="Output file name without extension", default="inventoryout")
    parcer.add_argument('-C', type=str, help="Context", default="DC")

    logging.basicConfig(filename="invent.log", level=logging.INFO)
    logging.info("Start Inventory Process")

    args = parcer.parse_args()
    cp = configparser.ConfigParser()
    cp.read(args.f)
    ipaddrs = cp.get('access','switches')
    ipaddrslist = ipaddrs.split('\n')
    if DEBUGGPRINT:
        print(ipaddrslist)

    hashlist = ["sha","md5","none"]
    enclist = ["none","aes128","aes192","aes256","des","3des"]
    snmpuserorcom = ""
    authpass = ""
    privpass = ""
    authtype = ""
    privtype = ""
    rootswitchip = ""
    contextname = ""

    args = parcer.parse_args()
    if args.v == 2:
        if args.c != None and len(args.c) > 3:
            print("Use v2c and community "+args.c)
            snmpuserorcom = args.c
        else:
            print("Invalid community")
            exit(1)

    elif args.v == 3:
        if args.a in hashlist and args.x in enclist:
            if len(args.u) <3:
                print("Wrong userdata")
                exit(1)
            if args.x != "none":
                if len(args.X) < 3:
                    print("Wrong userdata")
                    exit(1)
            if args.A != "none":
                if len(args.A) <3:
                    print("Wrong userdata")
                    exit(1)

            snmpuserorcom = args.u
            authpass = args.A
            privpass = args.X
            authtype = args.a
            privtype = args.x
            contextname = args.C
        else:
            print("Invalid hashalg or privalg")
            exit(1)

    devicesall = Devices()

    root = ET.Element("switches")

    if len(ipaddrslist) > 0:
        GoWithSnmp1 = GoWithSnmp(ipaddrslist[0], args.v, snmpuserorcom, authpass, privpass, authtype, privtype,contextname)
        print("Context: "+contextname)
    for ipa in ipaddrslist:
        if DEBUGGPRINT:
            print(ipa)
        devicesall.devlist.append(Device(ipa))


        rtname = GoWithSnmp1.getoiddata(ipa, sysnameoid)
        if rtname == None:
            print("No Response!")
            logging.error("Host: "+ipa+" no response!")
            continue
        else:

            logging.info("Host: "+ipa+" inventory OK")

            modeln = GoWithSnmp1.getoiddata(ipa, stoidmodel)
            if modeln == None:
                modelnt = ""
            else:
                modelnt = modeln[1]

            rtsysdescription = GoWithSnmp1.getoiddata(ipa, sysdescroid)
            if rtsysdescription != None:
                if rtsysdescription[1][0:2] == "0x":
                    stt1 = codecs.decode(codecs.decode(rtsysdescription[1][2:], "hex"), "ascii")
                else:
                    stt1 = rtsysdescription[1]

            rtsyslocation = GoWithSnmp1.getoiddata(ipa, syslocationoid)
            if rtsyslocation == None:
                rtsyslocation = ""



            swr = ET.SubElement(root,"sw")
            ast = ET.SubElement(swr,"name").text = rtname[1]
            sip = ET.SubElement(swr,"ip").text = ipa
            sloc = ET.SubElement(swr, "location").text = rtsyslocation[1]
            sinv = ET.SubElement(swr,"inv")
            if DEBUGGPRINT:
                print(rtname[1] + "\r\n" + "\r\n" + rtsyslocation[1])

            invrec = ET.SubElement(sinv,"invrec")
            invrecin = ET.SubElement(invrec,"modulename").text = modelnt
            invrecin2 = ET.SubElement(invrec,"SN").text = "not avalible"
    tree = ET.ElementTree(root)
    tree.write(args.o+".xml")
