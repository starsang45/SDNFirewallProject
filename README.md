# SDNFirewallProject
Georgia Tech master project (Network)
Objective
To implement a dynamic Software-Defined Networking (SDN) firewall using the POX controller. The firewall processes rules defined in configure.pol and enforces them on network traffic. The implementation is tested using simulated network traffic in a Mininet environment.
Files in the Project
configure.pol: Defines the firewall rules.

Format: RuleNumber, Action, Source MAC, Destination MAC, Source IP, Destination IP, Protocol, Source Port, Destination Port, Comment/Note.
Rules include:
Blocking specific traffic (e.g., outbound TCP from cn4).
Allowing ICMP traffic between HQ and other corporate subnets.
Restricting access to specific ports (e.g., TCP 25 or 9250–9520).
sdn-firewall.py: The Python implementation of the firewall.

Parses configure.pol and translates rules into OpenFlow flow-mod messages.
Key features:
Uses the POX OpenFlow controller.
Supports matching on MAC, IP, Protocol, and Ports.
Implements rule priority for Allow/Block actions.
packetcapture.pcap: Captures network packets to verify the firewall behavior.

Used to analyze whether rules are applied correctly.
Firewall Rules in configure.pol
1, Block, -, -, 10.0.30.4/32, 0.0.0.0/0, 6, -, -, Block all outbound TCP traffic from cn4 to the world
2, Block, -, -, 10.0.30.5/32, 0.0.0.0/0, -, -, -, Block all outbound traffic from cn5
3, Allow, -, -, 10.0.0.0/24, 10.0.1.0/24, 1, -, -, Allow ICMP ping from HQ to US subnet
4, Block, -, -, 10.0.30.3/32, 0.0.0.0/0, 6, 80, -, Block HTTP response from cn3
5, Block, -, -, 10.0.40.128/28, 10.0.1.33/32, 6, 9250-9520, -, Block financial data access to us3

Key Functions in sdn-firewall.py
Firewall Policy Processing:

def firewall_policy_processing(policies):
    rules = []
    for policy in policies:
        rule = of.ofp_flow_mod()
        match = of.ofp_match()
        
        if policy['mac-src'] != '-':
            match.dl_src = EthAddr(policy['mac-src'])
        if policy['mac-dst'] != '-':
            match.dl_dst = EthAddr(policy['mac-dst'])
        if policy['ip-src'] != '-':
            match.nw_src = IPAddr(policy['ip-src'])
        if policy['ip-dst'] != '-':
            match.nw_dst = IPAddr(policy['ip-dst'])
        if policy['ipprotocol'] != '-':
            match.nw_proto = int(policy['ipprotocol'])
        if policy['port-src'] != '-':
            match.tp_src = int(policy['port-src'])
        if policy['port-dst'] != '-':
            match.tp_dst = int(policy['port-dst'])
        
        if policy['action'].lower() == 'block':
            rule.priority = 100
            rule.actions = []
        elif policy['action'].lower() == 'allow':
            rule.priority = 10
            rule.actions.append(of.ofp_action_output(port=of.OFPP_NORMAL))
        
        rule.match = match
        rules.append(rule)
    return rules

Testing
Test Setup in Mininet:

Use test-server.py and test-client.py scripts to simulate traffic.
Example commands:
Server (hq1): python test-server.py T 10.0.0.1 80
Client (cn4): python test-client.py T 10.0.0.1 80
Tasks Tested:

Blocking TCP traffic from cn4.
Isolating cn5 from the network.
Allowing ICMP traffic between HQ and US, UK, IN subnets.
Blocking financial data access to us3 and us4.

Submission
To submit the project, zip the required files using the following command:

zip gtlogin_sdn.zip packetcapture.pcap configure.pol sdn-firewall.py

Replace gtlogin with your GT login.

Conclusion
The project demonstrates the implementation of a dynamic SDN firewall, showcasing the use of OpenFlow in POX to enforce network security policies.

