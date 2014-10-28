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

Exports on /dist
```javascript
iptgen.exportFile("iptables.sh");
```