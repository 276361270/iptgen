var iptgen = require('./iptgen.js');
var ipt_dofus = require('./ipt_dofus.js');

//Disables ICMP protocol
iptgen.new_input().icmp().drop().saveRule();

//Drop badbot hosts (ecatel, dshield botnet list, bruteforcers)
iptgen.new_addr_list("badbots", iptgen.new_input()).drop().saveRule();

//Drop invalid tcp traffic
iptgen.new_input().m_state(iptgen.STATES.INVALID).drop().saveRule();

//Log unknown hosts (used by an host reputation service)
var new_addr_rule = iptgen.new_input().protocol("tcp --syn").module("recent --name new_address_to_log ! --rcheck");
new_addr_rule.clone().target('LOG --log-level info --log-prefix " iptables.new_ip_logged "').saveRule();
new_addr_rule.clone().module('recent --name new_address_to_log --set').saveRule();

var web_ports = [80, 443];
//Allow cloudflare(http/https reverse proxy) only on web ports
var cf = iptgen.new_addr_list("cloudflare", iptgen.new_input());
cf.clone().tcp().dst_ports(web_ports).allow().saveRule();
cf.clone().drop().saveRule();
//Disable other hosts on web ports
iptgen.new().tcp().dst_ports(web_ports).drop().saveRule();

//Layer7 filtering for Dofus2 AUTH server
iptgen.new_l7_restrict_filter(
    [5555],

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

//Layer7 filtering for Dofus2 WORLD server
iptgen.new_l7_restrict_filter(
    [5556],

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

    //d2 server sends auth_ticket_accepted or auth_ticket_refused packet
    // => good protocol used by the guest host
    // => guest host is a valid host for 30 minutes
    function(match){
        ipt_dofus.match_packet(match, ipt_dofus.SIGNATURES.auth_ticket_accepted);
        ipt_dofus.match_packet(match, ipt_dofus.SIGNATURES.auth_ticket_refused);
    }
);

iptgen.exportFile("iptables.sh");