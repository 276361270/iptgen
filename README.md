iptgen
==============
>>Iptables rules generator using NodeJS

### How to import? ###
1. Go to iptgen folder
2. Use `npm install`
3. Open the project on ur editor
4. The main file is ./app.js

### Lists ###
U can add news ip lists on the /lists folder, with the .list extension.

###  Exemples of codes ###
A complete code example is stored on ./app.js

Includes the generator
```javascript
var iptgen = require('./iptgen.js');
```

Simple match/allow exemple and saves the rule
```javascript
iptgen.new_inputRule()
    .append()
    .tcp()
    .src_addr("127.0.0.1")
    .allow()
    .saveRule();
```

Match using .list file  and saves the rules
```javascript
iptgen.new_addrListRule("badbots",
    iptgen.new_inputRule()
        .append()
        .tcp()
        .dst("127.0.0.1", 443)
).m_connflood(20, 30).rejectWith(iptgen.REJECTS.TCP_RESET).saveRule();
```

Restrictions based on server response packet matching :

```javascript
//Layer7 filtering for Dofus2 AUTH server
iptgen.new_l7_restrict_filter(
    [5555], //port 5555

    //guest host can have max 10 simultaneous connections
    //guest host can create 5 connections on 30 seconds
    function(guest) {
        guest.clone().m_connlimit(10).drop().saveRule();
        guest.clone().m_connflood(30, 5).drop().saveRule();
        guest.clone().allow().saveRule();
    },

    //valid host can have max 20 simultaneous connections
    //valid host can create 10 connections on 5 seconds
    function(valid) {
        valid.clone().m_connlimit(20).drop().saveRule();
        valid.clone().m_connflood(5, 10).drop().saveRule();
        valid.clone().allow().saveRule();
    },

    //d2 server sends auth_success or auth_failed or banned packet
    // => good protocol used by the guest host
    // => guest host is a valid host for 30 minutes
    function(match){
        ipt_dofus.match_packet(match, ipt_dofus.SIGNATURES.auth_fail);
        ipt_dofus.match_packet(match, ipt_dofus.SIGNATURES.auth_success);
        ipt_dofus.match_packet(match, ipt_dofus.SIGNATURES.banned);
    }
);
```

Exports on /dist
```javascript
iptgen.exportFile("iptables.sh");
```

All "rule" functions

```javascript
/*
 * Save the rule
 */
    this.saveRule = function();

/*
 * Targets
 */
    this.target = function(chain);
    this.allow = function();
    this.drop = function();
    this.reject = function();

    /*
        REJECTS = {
            TCP_RESET : "tcp-reset",
            ICMP_PORT_UNREACHABLE : "icmp-port-unreachable",
            ICMP_NET_UNREACHABLE : "icmp-net-unreachable",
            ICMP_HOST_UNREACHABLE : "icmp-host-unreachable",
            ICMP_PROTO_UNREACHABLE : "icmp-proto-unreachable",
            ICMP_NET_PROHIBITED : "icmp-net-prohibited",
            ICMP_HOST_PROHIBITED : "icmp-host-prohibited"
        };
    */
    this.rejectWith = function(rwith);
    this.return = function();

/*
 * Actions
 */
    this.append = function();
    this.insert = function();
    this.delete = function();

/*
 * Protocol
 */
    this.protocol = function(protocol);
    this.tcp = function();
    this.udp = function();
    this.udpFragmented = function();
    this.icmp = function();

/*
 * Origin-matching
 */
    this.src_addr = function(ip);
    this.src_port = function(port);
    this.src_ports = function(ports);
    this.src = function(ip, port);

/*
 * Destination-matching
 */
    this.dst_addr = function(ip);
    this.dst_port = function(port);
    this.dst_ports = function(ports);
    this.dst = function(ip, port);

/*
 * Interface-matching
 */
    this.in = function(iface);
    this.out = function(iface);

/*
 * Modules
 */

    /*
        PKTTYPES = {
            MULTICAST : "multicast",
            BROADCAST : "broadcast"
        };
    */
    
    this.m_pkttype = function(type);

    /*
        STATES = {
            CONNECTED : "ESTABLISHED,RELATED",
            NEW : "NEW",
            UNTRACKED : "UNTRACKED",
            INVALID : "INVALID"
        };
    */

    this.m_state = function(states);

    this.m_connlimit = function(max);
    this.m_connflood = function(interval, hits);

    /*
        example packet_options: {str: "hello", from: 0, to: 4}
    */
    this.m_match_string = function(packet_options);

    /*
        example packet_options: {hex: "00 59", from: 54, to: 55}
    */
    this.m_match_hex = function(packet_options);

    this.has_token = function(name, timeout);
    this.set_token = function(name, isDest);

    this.module = function(modOpts);
```
