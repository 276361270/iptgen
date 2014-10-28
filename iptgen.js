var fs = require('fs');
var crypto = require('crypto');

var file_headers = ["#!/bin/sh", "#generated with iptgen"];
var file_rules_chains = [];
var file_rules_appends = [];
var file_rules_inserts = [];
var file_rules_deletes = [];

exports.REJECTS = {
    TCP_RESET : "tcp-reset",
    ICMP_PORT_UNREACHABLE : "icmp-port-unreachable",
    ICMP_NET_UNREACHABLE : "icmp-net-unreachable",
    ICMP_HOST_UNREACHABLE : "icmp-host-unreachable",
    ICMP_PROTO_UNREACHABLE : "icmp-proto-unreachable",
    ICMP_NET_PROHIBITED : "icmp-net-prohibited",
    ICMP_HOST_PROHIBITED : "icmp-host-prohibited"
};

exports.PKTTYPES = {
    MULTICAST : "multicast",
    BROADCAST : "broadcast"
};

exports.STATES = {
    CONNECTED : "ESTABLISHED,RELATED",
    NEW : "NEW",
    UNTRACKED : "UNTRACKED",
    INVALID : "INVALID"
};

String.prototype.hashCode = function(){
    var string = crypto.createHash('md5').update(this.toString()).digest("hex");
    var hash = 0;
    var length = string.length;

    for (var i = 0; i < length; i++) {
        hash = ((hash * 31) + string.charCodeAt(i)) & 0x7fffffff;
    }

    return (hash === 0) ? 1 : hash;
};

Object.prototype.hashCode_cache = null;
Object.prototype.hashCode = function() {
    if(this.hashCode_cache == null)
        this.hashCode_cache = JSON.stringify(this).hashCode();
    return this.hashCode_cache;
};

Object.prototype.clone = function() {
   return JSON.parse(JSON.stringify(this));
}

function rule() {
    this.options = {chain:"INPUT", action:"-A"};

    this.clone = function () {
        var rl = new rule();
        rl.options = this.options.clone();
        return rl;
    };

    this.chain = function(chain) {
        this.options.chain = chain;
        return this;
    };

    /*
     * Targets
     */
    this.target = function(chain) {
        this.options.target = chain;
        return this;
    };

    this.allow = function() {
        this.options.target = 'ACCEPT';
        return this;
    };

    this.drop = function() {
        this.options.target = 'DROP';
        return this;
    };

    this.reject = function() {
        this.options.target = 'REJECT';
        return this;
    };

    this.rejectWith = function(rwith) {
        this.options.target = 'REJECT --reject-with ' + rwith;
        return this;
    };

    this.return = function() {
        this.options.target = 'RETURN';
        return this;
    };

    /*
     * Actions
     */
    this.append = function() {
        this.options.action = '-A';
        return this;
    };

    this.insert = function() {
        this.options.action = '-I';
        return this;
    };

    this.delete = function() {
        this.options.action = '-D';
        return this;
    };

    /*
     * Protocol
     */
    this.protocol = function(protocol) {
        this.options.protocol = protocol;
        return this;
    };
    this.tcp = function() {
        this.options.protocol = "TCP";
        return this;
    };
    this.udp = function() {
        this.options.protocol = "UDP";
        return this;
    };
    this.udpFragmented = function() {
        this.options.protocol = "UDP -f";
        return this;
    };
    this.icmp = function() {
        this.options.protocol = "ICMP";
        return this;
    };

    /*
     * Origin-matching
     */
    this.src_addr = function(ip) {
        this.options.src = ip;
        return this;
    };
    this.src_port = function(port) {
        this.options.sport = port;
        return this;
    };
    this.src_ports = function(ports) {
        this.options.sports = ports;
        return this;
    };
    this.src = function(ip, port) {
        this.options.src = ip;
        this.options.sport = port;
        return this;
    };

    /*
     * Destination-matching
     */
    this.dst_addr = function(ip) {
        this.options.dst = ip;
        return this;
    };
    this.dst_port = function(port) {
        this.options.dport = port;
        return this;
    };
    this.dst_ports = function(ports) {
        this.options.dports = ports;
        return this;
    };
    this.dst = function(ip, port) {
        this.options.dst = ip;
        this.options.dport = port;
        return this;
    };

    /*
     * Interface-matching
     */
    this.in = function(iface) {
        this.options.in = iface;
        return this;
    };
    this.out = function(iface) {
        this.options.out = iface;
        return this;
    };

    this.saveRule = function() {
        exports.saveRule(this);
        return this;
    };

    /*
     * Modules
     */

    this.m_connlimit = function(max) {
        this.options.module = "connlimit --connlimit-above "+(max+1);
        return this;
    };

    this.m_pkttype = function(type) {
        this.options.module = "pkttype --pkt-type "+type;
        return this;
    };

    this.m_state = function(states) {
        this.options.module = "state --state "+states;
        return this;
    };

    this.m_connflood = function(interval, hits) {
        this.options.module = "state --state NEW -m recent --name "+this.hashCode()+" --update --seconds "+interval+" --hitcount "+hits+" --rttl";
        var pre_rule = new rule();
        pre_rule.options = this.options.clone();
        pre_rule.options.module = "state --state NEW -m recent --name "+this.hashCode()+" --set";
        pre_rule.saveRule();
        return this;
    };

    this.m_match_string = function(packet_options) {
        if(!packet_options.str) {
            throw new Error("Packet str forgotten.");
        }
        packet_options.str = packet_options.str.replace(/"/g, "\\\"");
        var module = 'string ';
        if(packet_options.from) module += "--from " + packet_options.from + " ";
        if(packet_options.to) module += "--to " + packet_options.to + " ";
        module += "--algo bm ";
        module += "--string \"" + packet_options.str + "\"";
        this.options.module = module;
        return this;
    };

    this.m_match_hex = function(packet_options) {
        if(!packet_options.hex) {
            throw new Error("Packet hex dump forgotten.");
        }
        var module = 'string ';
        if(packet_options.from) module += "--from " + packet_options.from + " ";
        if(packet_options.to) module += "--to " + packet_options.to + " ";
        module += "--algo bm ";
        module += "--hex-string \"|" + packet_options.hex + "|\"";
        this.options.module = module;
        return this;
    };

    this.has_token = function(name, timeout) {
        if(!this.options.module)this.options.module = "recent --name "+name+" --update --seconds "+timeout+" --hitcount 1 --rttl";
        else this.options.module += " -m recent --name "+name+" --update --seconds "+timeout+" --hitcount 1 --rttl ";
        return this;
    };

    this.set_token = function(name, isDest) {
        if(!this.options.module)this.options.module = "recent --name "+name+" --set";
        else this.options.module += " -m recent --name "+name+" --set ";
        if(isDest)this.options.module += " --rdest ";
        return this;
    };

    this.module = function(m) {
        if(!this.options.module)this.options.module = m;
        else this.options.module+= " -m "+m;
        return this;
    };

}

exports.new = function () {
    return new rule();
};

exports.new_input = function () {
    return new rule().chain("INPUT");
};

exports.new_forward = function () {
    return new rule().chain("FORWARD");
};

exports.new_output = function () {
    return new rule().chain("OUTPUT");
};

exports.new_chain = function (name) {
    var new_chain = "iptables -N " + name;
    if(file_rules_chains.indexOf(new_chain) == -1) {
        file_rules_chains.push(new_chain);
    }
    return name;
}

exports.new_l7_restrict_filter = function (ports, restrict_guest, restrict_valid , match, byInput) {
    var l_established = this.new_chain("ESTABLISHED_CONNECTION"),
        l_toFilter = this.new_chain(ports.hashCode() + "_tf"),
        l_valid = this.new_chain(ports.hashCode() + "_valid"),
        l_match = this.new_chain(ports.hashCode() + "_match");

    var valid_host_token = ports.hashCode() + "_valid_token";

    this.new_input().m_state(this.STATES.CONNECTED).target(l_established).saveRule();
    this.new().chain(l_established).tcp().dst_ports(ports).target(l_toFilter).saveRule();

    this.new_input().append().tcp().dst_ports(ports).m_state(this.STATES.NEW)
        .has_token(valid_host_token, 1800).target(l_valid).saveRule();

    restrict_guest(this.new_input().append().tcp().dst_ports(ports));
    this.new().chain(l_valid).set_token(valid_host_token).saveRule();
    restrict_valid(this.new().chain(l_valid));

    this.new().chain(l_toFilter).has_token(valid_host_token, 1800).allow().saveRule();

    if(byInput) {
        match(this.new_input().tcp().dst_ports(ports).target(l_match));
        this.new().chain(l_match).set_token(valid_host_token).saveRule();
    }else {
        match(this.new_output().tcp().src_ports(ports).target(l_match));
        this.new().chain(l_match).set_token(valid_host_token, true).saveRule();
    }

    this.new().chain(l_toFilter).allow().saveRule();
    this.new().chain(l_match).allow().saveRule();
};

exports.new_addr_list = function(name, tpl_rule, isDst) {
    var file_list = "lists/"+name+".list";
    var m_chain = exports.new_chain(file_list.hashCode());
    var addresses = fs.readFileSync(file_list).toString().split("\n");
    tpl_rule.target(m_chain);
    for(var i=0;i<addresses.length;i++) {
        var addr = addresses[i];
        if(addr == null)continue;
        addr = addr.trim();
        if(addr.length == 0) continue;
        var rl = tpl_rule.clone();
        if(isDst)rl.dst_addr(addr)
        else rl.src_addr(addr);
        rl.saveRule();
    }
    return new rule().chain(m_chain);
}

exports.saveRule = saveRule;

function genLine(rule) {
    var args = iptablesArgs(rule);

    var cmd = 'iptables ';
    if (rule.sudo) {
        cmd = 'sudo ';
        args = ['iptables'].concat(args);
    }
    var line = concat(cmd, args, " ");

    var target;
    switch(rule.action) {
        case "-D":
            target = file_rules_deletes;
            break;
        case "-I":
            target = file_rules_inserts;
            break;
        case "-A":
        default:
            target = file_rules_appends;
            break;
    }
    if(target.indexOf(line) == -1)
        target.push(line);
}

function iptablesArgs(rule) {
    var args = [];

    if (!rule.chain) rule.chain = 'INPUT';

    if (rule.chain) args = args.concat([rule.action, rule.chain]);
    if (rule.protocol) args = args.concat(["-p", rule.protocol]);
    if (rule.src) args = args.concat(["-s", rule.src]);
    if (rule.dst) args = args.concat(["-d", rule.dst]);
    if (rule.sports){
        args = args.concat(["-m multiport --sports", "".concat(rule.sports)]);
    } else if (rule.sport) args = args.concat(["--sport", rule.sport]);
    if (rule.dports) {
        args = args.concat(["-m multiport --dports", "".concat(rule.dports)]);
    } else if (rule.dport) args = args.concat(["--dport", rule.dport]);
    if (rule.in) args = args.concat(["-i", rule.in]);
    if (rule.out) args = args.concat(["-o", rule.out]);
    if (rule.module) args = args.concat(["-m", rule.module]);
    if (rule.target) args = args.concat(["-j", rule.target]);

    return args;
}

function concat(str, args, separator) {
    for (var i = 0; i < args.length; i++) {
        if (i > 0) str += separator;
        str += args[i];
    }
    return str;
}

function saveRule(rule) {
    genLine(rule.options);
}

exports.exportFile = function exportFile(name) {
    var fileContent = "";
    fileContent = concat(fileContent, file_headers, "\n") + "\n";
    fileContent = concat(fileContent, file_rules_chains, "\n") + "\n";
    fileContent = concat(fileContent, file_rules_appends, "\n") + "\n";
    fileContent = concat(fileContent, file_rules_inserts, "\n") + "\n";
    fileContent = concat(fileContent, file_rules_deletes, "\n");

    try { fs.mkdirSync("dist"); } catch(e){}

    fs.writeFile("dist/"+name, fileContent , function (err) {
        if (err) {
            console.log(err);
        } else {
            console.log("Rules saved on "+ name +"!");
        }
    });
};