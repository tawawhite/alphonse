#[macro_export]
macro_rules! add_none_dpi_rule {
    ($hs_pattern:literal, $trans_protocol: expr, $parser: expr, $manager: expr) => {{
        let rule_id = $manager.add_simple_dpi_rule($parser.id, $hs_pattern, $trans_protocol)?;
        $parser.match_cbs.insert(rule_id, MatchCallBack::None);
        match &$manager.get_rule(rule_id).unwrap().rule_type {
            RuleType::DPI(rule) => rule.hs_pattern.id.unwrap(),
            _ => unreachable!(),
        }
    }};
}

#[macro_export]
macro_rules! add_none_dpi_tcp_rule {
    ($hs_pattern:literal, $parser: expr, $manager: expr) => {
        add_none_dpi_rule!($hs_pattern, dpi::Protocol::TCP, $parser, $manager)
    };
}

#[macro_export]
macro_rules! add_none_dpi_udp_rule {
    ($hs_pattern:literal, $parser: expr, $manager: expr) => {
        add_none_dpi_rule!($hs_pattern, dpi::Protocol::UDP, $parser, $manager)
    };
}
