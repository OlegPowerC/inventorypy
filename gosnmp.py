from pysnmp.hlapi import *
import codecs

class Port:
    def __init__(self,porti,portn,cdprno):
        self.portindex = porti
        self.portname = portn
        self.cdprecordno = cdprno

class SwitchRouter:
    def __init__(self,ipaddr):
        self.ipaddress = ipaddr
        self.portlist = []

class GoWithSnmp:
    def __init__(self,roothost,snmpver,usernameorcom,authpass,privpass,authtype,privtype,contextname=""):
        self.roothost_ip = roothost
        self.snmpv3usernameorcomm = usernameorcom
        self.authpassword = authpass
        self.privpassword = privpass
        self.snmpport = 161
        self.switchesrouters = []
        self.switchidinthree = 0
        self.snmpversion = snmpver
        self.context = contextname
        if self.snmpversion == 3:
            if authtype == "sha":
                self.snmpv3hash = (1, 3, 6, 1, 6, 3, 10, 1, 1, 3)
            elif authtype == "md5":
                self.snmpv3hash = (1, 3, 6, 1, 6, 3, 10, 1, 1, 2)
            elif authtype == "none":
                self.snmpv3hash = (1, 3, 6, 1, 6, 3, 10, 1, 1, 1)
            else:
                print("Invalid auth protocol")
                exit(1)
            if privtype == "aes128":
                self.snmpv3encryption = (1, 3, 6, 1, 6, 3, 10, 1, 2, 4)
            elif privtype == "aes192":
                self.snmpv3encryption = (1, 3, 6, 1, 4, 1, 9, 12, 6, 1, 1)
            elif privtype == "aes256":
                self.snmpv3encryption = (1, 3, 6, 1, 4, 1, 9, 12, 6, 1, 2)
            elif privtype == "des":
                self.snmpv3encryption = (1, 3, 6, 1, 6, 3, 10, 1, 2, 2)
            elif privtype == "3des":
                self.snmpv3encryption =  (1, 3, 6, 1, 6, 3, 10, 1, 2, 3)
            elif privtype == "none":
                self.snmpv3encryption = usmNoPrivProtocol
            else:
                print("Invalid priv protocol")
                exit(1)
            self.snmprootudata = UsmUserData(self.snmpv3usernameorcomm, self.authpassword, self.privpassword, self.snmpv3hash,
                                             self.snmpv3encryption)
        elif self.snmpversion == 2:
            self.snmprootudata = CommunityData(self.snmpv3usernameorcomm)
            print(self.snmpv3usernameorcomm)
        self.snmproothostdata = UdpTransportTarget((self.roothost_ip, self.snmpport))
        self.switchesrouters.append(SwitchRouter(self.roothost_ip))
        self.platformtype = "NONE"
        self.intind = 2
        self.cdprind = 1

    def convertsnmpiphexttostring(self,snmpip):
        try:
            iip = int(snmpip, 16)
            if iip != 0:
                octet4 = iip & 0xff
                octet3 = (iip >> 8) & 0xff
                octet2 = (iip >> 16) & 0xff
                octet1 = iip >> 24
                stripi = str(octet1) + "." + str(octet2) + "." + str(octet3) + "." + str(octet4)
                return stripi
            else:
                return "NoData"
        except:
            return "NoData"

    def getoiddata(self,swip, oid):
        hostdata = UdpTransportTarget((swip, 161))
        for (errorIndication, errorStatus, errorIndex, varBinds) in getCmd(SnmpEngine(), self.snmprootudata, hostdata,ContextData(contextName=self.context), ObjectType(ObjectIdentity(oid)), lexicographicMode=True, lookupMib=False):
            if errorIndication:
                print(errorIndication)
                return
            elif errorStatus:
                print('%s at %s' % (errorStatus.prettyPrint(),errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
                return
            else:
                for name, val in varBinds:
                    return name.prettyPrint(), val.prettyPrint()
    def nextoiddata(self,swip, oid, lexmode=True):
        hostdata = UdpTransportTarget((swip, 161))
        for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(SnmpEngine(), self.snmprootudata, hostdata,ContextData(contextName=self.context), ObjectType(ObjectIdentity(oid)), lexicographicMode=lexmode, lookupMib=False):
            if errorIndication:
                print(errorIndication)
                return
            elif errorStatus:
                print('%s at %s' % (errorStatus.prettyPrint(),errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
                return
            else:
                for name, val in varBinds:
                    return name.prettyPrint(), val.prettyPrint()

    def walkoiddata(self,swip, oid, lexmode=True):
        hostdata = UdpTransportTarget((swip, 161))
        retdata = []
        for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(SnmpEngine(), self.snmprootudata, hostdata,ContextData(contextName=self.context), ObjectType(ObjectIdentity(oid)), lexicographicMode=lexmode, lookupMib=False):
            if errorIndication:
                print(errorIndication)
                return
            elif errorStatus:
                print('%s at %s' % (errorStatus.prettyPrint(),errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
                return
            else:
                retdata.append(varBinds)
                #print(varBinds)
        return retdata

    def getcurrentswdata(self):
        sysnameoid = "1.3.6.1.2.1.1.5"
        sysdescroid = "1.3.6.1.2.1.1.1"

        rtname = self.nextoiddata(self.roothost_ip, sysnameoid)

        if rtname != None:
            print(rtname[1])

        rtsysdescription = self.nextoiddata(self.roothost_ip, sysdescroid,True)

        if rtsysdescription != None:
            if rtsysdescription[1][0:2] == "0x":
                stt1 = codecs.decode(codecs.decode(rtsysdescription[1][2:], "hex"), "ascii")
                print(stt1)
            else:
                stt1 = rtsysdescription[1]
            print(stt1)
            self.platformtype = stt1

            if self.platformtype.find("NX-OS") != -1:
                self.intind = 2
                print("Nexus Platform found!")
            elif self.platformtype.find("Cisco IOS") != -1:
                self.intind = 2
                print("Cisco IOS Platform found!")
            else:
                print("OtherPlatform")
                self.intind = 2

    def walkallports(self):
        for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(SnmpEngine(), self.snmprootudata, self.snmproothostdata,ContextData(contextName=self.context), ObjectType(ObjectIdentity('1.3.6.1.4.1.9.9.23.1.2.1.1.7')), lexicographicMode=False, lookupMib=False):
            if errorIndication:
                print(errorIndication)
                break
            elif errorStatus:
                print('%s at %s' % (errorStatus.prettyPrint(),
                                    errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
                break
            else:
                for name, val in varBinds:
                    fulloid = name.prettyPrint()
                    flast = fulloid.split('.')
                    self.switchesrouters[self.switchidinthree].portlist.append(Port(flast[len(flast) - self.intind], "",flast[len(flast) - self.cdprind]))


        for portelement in self.switchesrouters[self.switchidinthree].portlist:
            oidportname = "1.3.6.1.2.1.31.1.1.1.1."+portelement.portindex
            self.rts2 = self.getoiddata(self.roothost_ip, oidportname)
            if self.rts2 != None:
                portelement.portname = self.rts2[1]
            else:
                print("NoData")