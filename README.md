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
