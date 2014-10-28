exports.SIGNATURES = {
    auth_success: [
        {hex: "00 59", from: 54, to: 55},
        {hex: "00 5a", from: 54, to: 55},
        {hex: "00 5b", from: 54, to: 55}
    ],
    auth_fail: [
        {hex: "00 52", from: 54, to: 55},
        {hex: "00 53", from: 54, to: 55},
        {hex: "00 54", from: 54, to: 55}
    ],
    auth_ticket_accepted: [
        {hex: "01 bc", from: 54, to: 55}
    ],
    auth_ticket_refused: [
        {hex: "01 c0", from: 54, to: 55}
    ],
    banned : [
        {hex: "60 79", from: 54, to: 55},
        {hex: "60 7a", from: 54, to: 55},
        {hex: "60 7b", from: 54, to: 55}
    ]
};

exports.match_packet = function(rule_tpl, signatures) {
    for(var i=0; i<signatures.length; i++) {
        rule_tpl.clone().m_match_hex(signatures[i]).saveRule();
    }
};