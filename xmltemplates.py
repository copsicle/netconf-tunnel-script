tunnel_filter = """
<filter xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
        <interface>
            <Tunnel>
                <name />
            </Tunnel>
        </interface>
    </native>
</filter>
"""

identical_tunnel_filter = """
<filter xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
        <interface>
            <Tunnel>
                <name />
                <ip />
                <tunnel xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-tunnel">
                    <destination>
                        <ipaddress-or-host>{}</ipaddress-or-host>
                    </destination>
                    <protection>
                        <ipsec xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-crypto">
                            <profile-option>
								<name>{}</name>
							</profile-option>
                        </ipsec>
                    </protection>
                </tunnel>
            </Tunnel>
        </interface>
    </native>
</filter>
"""

hostname_filter = """
<filter xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
        <hostname />
    </native>
</filter>
"""

tunnel_config = """
<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
        <interface>
            <Tunnel>
                <name>{}</name>
                <description>GRE/IPsec Tunnel To {} (Tunnel{})</description>
                <ip>
                    <address>
                        <primary>
                            <address>{}</address>
                            <mask>{}</mask>
                        </primary>
                    </address>
                </ip>
                <logging>
                    <event>
                        <link-status/>
                    </event>
                </logging>
                <tunnel xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-tunnel">
                    <source>{}</source>
                    <destination>
                        <ipaddress-or-host>{}</ipaddress-or-host>
                    </destination>
                    <protection>
                        <ipsec xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-crypto">
                            <profile-option>
								<name>{}</name>
							</profile-option>
                        </ipsec>
                    </protection>
                </tunnel>
            </Tunnel>
        </interface>
    </native>
</config>
"""

ospf_proc_config = """
<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
        <router>
            <router-ospf xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-ospf">
                <ospf>
                    <process-id>
                        <id>{}</id>
                        <passive-interface>
                            <interface operation="delete">Tunnel{}</interface>
                        </passive-interface>
                    </process-id>
                </ospf>
            </router-ospf>
        </router>
    </native>
</config>
"""

ospf_int_config = """
<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
        <interface>
            <Tunnel>
                <name>{}</name>
                <ip>
                    <router-ospf xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-ospf">
                        <ospf>
                            <process-id>
                                <id>{}</id>
                                <area>
                                    <area-id>{}</area-id>
                                </area>
                            </process-id>
                            <network>
                                <point-to-point/>
                            </network>
                        </ospf>
                    </router-ospf>
                </ip>
            </Tunnel>
        </interface>
    </native>
</config>
"""

ipsec_trset_config = """
<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
        <crypto>
            <ipsec xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-crypto">
                <transform-set>
                    <tag>{}</tag>
                    <esp>{}</esp>
                    <key-bit>{}</key-bit>
                    <mode>
                        <tunnel/>
                    </mode>
                </transform-set>
            </ipsec>
        </crypto>
    </native>
</config>
"""

trset_filter = """
<filter xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
        <crypto>
            <ipsec xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-crypto">
                <transform-set />
            </ipsec>
        </crypto>
    </native>
</filter>
"""

isakmp_key_config = """
<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
        <crypto>
            <isakmp xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-crypto">
                <key>
                    <key-address>
                        <key>{}</key>
                        <addr4-container>
                            <address>{}</address>
                        </addr4-container>
                    </key-address>
                </key>
            </isakmp>
        </crypto>
    </native>
</config>
"""

isakmp_key_filter = """
<filter xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
        <crypto>
            <isakmp xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-crypto">
                <key>
                    <key-address>
                        <key />
                        <addr4-container>
                            <address>{}</address>
                        </addr4-container>
                    </key-address>
                </key>
            </isakmp>
        </crypto>
    </native>
</filter>
"""

isakmp_key_delete = """
<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
        <crypto>
            <isakmp xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-crypto">
                <key operation="delete">
                    <key-address>
                        <key>{}</key>
                        <addr4-container>
                            <address>{}</address>
                        </addr4-container>
                    </key-address>
                </key>
            </isakmp>
        </crypto>
    </native>
</config>
"""

isakmp_policy_config = """
<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
        <crypto>
            <isakmp xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-crypto">
                <policy>
                    <number>{}</number>
                    <authentication>{}</authentication>
                    <encryption>
                        <{}>
                            <key>{}</key>
                        </{}>
                    </encryption>
                    <group>{}</group>
                    <hash>{}</hash>
                    <lifetime>{}</lifetime>
                </policy>
            </isakmp>
        </crypto>
    </native>
</config>
"""

policy_filter = """
<filter xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
        <crypto>
            <isakmp xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-crypto">
                <policy />
            </isakmp>
        </crypto>
    </native>
</filter>
"""

policy_xpath = """
<filter type="xpath" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
 xmlns:ios="http://cisco.com/ns/yang/Cisco-IOS-XE-native" 
 xmlns:crypto="http://cisco.com/ns/yang/Cisco-IOS-XE-crypto"
 select="/ios:native/ios:crypto/crypto:isakmp/crypto:policy/*"/>
"""

ipsec_profile_config = """
<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
       <crypto>
            <ipsec xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-crypto">
                <profile>
                    <name>{}</name>
                    <description>Standard Profile For IPsec Tunnels</description>
                    <set>
                        <pfs>
                            <group>{}</group>
                        </pfs>
                        <transform-set>{}</transform-set>
                    </set>
                </profile>
            </ipsec>
        </crypto>
    </native>
</config>
"""

profile_filter = """
<filter xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
       <crypto>
            <ipsec xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-crypto">
		        <profile />
            </ipsec>
        </crypto>
    </native>
</filter>
"""

profile_xpath = """
<filter type="xpath" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
 xmlns:ios="http://cisco.com/ns/yang/Cisco-IOS-XE-native" 
 xmlns:crypto="http://cisco.com/ns/yang/Cisco-IOS-XE-crypto"
 select="/ios:native/ios:crypto/crypto:ipsec/crypto:profile/*"/>
"""

interface_address_filter = """
<filter xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
        <interface>
			<{}>
				<name>{}</name>
				<ip>
					<address>
						<primary>
							<address />
                        </primary>
                    </address>
                </ip>
            </{}>
        </interface>
    </native>
</filter>
"""

interface_address_filter_xpath = """
<filter type="xpath" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
 xmlns:ios="http://cisco.com/ns/yang/Cisco-IOS-XE-native"
 select="/ios:native/ios:interface/*[ios:ip/ios:address/ios:primary/ios:address='{}']"/>
"""