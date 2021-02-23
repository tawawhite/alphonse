/// Add a simple DPI rule
#[macro_export]
macro_rules! add_simple_dpi_rule {
    ($hs_pattern:literal, $trans_protocol: expr, $id: expr, $manager: expr) => {{
        let mut dpi_rule = dpi::Rule::new(pattern! {$hs_pattern});
        dpi_rule.protocol = $trans_protocol;
        let mut rule = Rule::new($id);
        rule.rule_type = RuleType::DPI(dpi_rule);
        $manager.add_rule(&mut rule)?
    }};
    ($hs_pattern:expr, $trans_protocol: expr, $id: expr, $manager: expr) => {{
        let mut dpi_rule = dpi::Rule::new($hs_pattern);
        dpi_rule.protocol = $trans_protocol;
        let mut rule = Rule::new($id);
        rule.rule_type = RuleType::DPI(dpi_rule);
        $manager.add_rule(&mut rule)?
    }};
}

/// Add a simple TCP DPI rule
#[macro_export]
macro_rules! add_simple_dpi_tcp_rule {
    ($hs_pattern:literal, $id: expr, $manager: expr) => {
        add_simple_dpi_rule!($hs_pattern, dpi::Protocol::TCP, $id, $manager)
    };
    ($hs_pattern:expr, $id: expr, $manager: expr) => {
        add_simple_dpi_rule!($hs_pattern, dpi::Protocol::TCP, $id, $manager)
    };
}

/// Add a simple UDP DPI rule
#[macro_export]
macro_rules! add_simple_dpi_udp_rule {
    ($hs_pattern:literal, $id: expr, $manager: expr) => {
        add_simple_dpi_rule!($hs_pattern, dpi::Protocol::UDP, $id, $manager)
    };
    ($hs_pattern:expr, $id: expr, $manager: expr) => {
        add_simple_dpi_rule!($hs_pattern, dpi::Protocol::UDP, $id, $manager)
    };
}

/// Add a simple TCP & UDP DPI rule
#[macro_export]
macro_rules! add_simple_dpi_tcp_udp_rule {
    ($hs_pattern:literal, $id: expr, $manager: expr) => {
        add_simple_dpi_rule!(
            $hs_pattern,
            $protocol,
            dpi::Protocol::TCP | dpi::Protocol::UDP,
            $id,
            $manager
        )
    };
    ($hs_pattern:expr, $id: expr, $manager: expr) => {
        add_simple_dpi_rule!(
            $hs_pattern,
            $protocol,
            dpi::Protocol::TCP | dpi::Protocol::UDP,
            $id,
            $manager
        )
    };
}
