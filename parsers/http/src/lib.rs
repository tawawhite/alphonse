extern crate alphonse_api;
extern crate anyhow;
extern crate hyperscan;
extern crate llhttp;

use alphonse_api as api;
use anyhow::Result;
use api::classifiers;
use api::parsers::ParserID;
use hyperscan::pattern;

#[derive(Clone)]
struct ProtocolParser {
    id: ParserID,
    name: String,
    classified: bool,
    parser: llhttp::Parser,
    settings: llhttp::Settings,
}

unsafe impl Send for ProtocolParser {}
unsafe impl Sync for ProtocolParser {}

impl ProtocolParser {
    fn new() -> Self {
        let settings = llhttp::Settings::new();
        ProtocolParser {
            id: 0,
            name: String::from("http"),
            classified: false,
            parser: llhttp::Parser::new(settings, llhttp::Type::BOTH),
            settings,
        }
    }
}

impl api::parsers::ProtocolParser for ProtocolParser {
    fn box_clone(&self) -> Box<dyn api::parsers::ProtocolParser> {
        Box::new(self.clone())
    }

    /// Get parser id
    fn id(&self) -> ParserID {
        self.id
    }

    /// Get parser id
    fn set_id(&mut self, id: ParserID) {
        self.id = id
    }

    /// Get parser name
    fn name(&self) -> String {
        self.name.clone()
    }

    fn register_classify_rules(
        &mut self,
        manager: &mut classifiers::ClassifierManager,
    ) -> Result<()> {
        let methods = vec![
            "DELETE",
            "GET",
            "HEAD",
            "POST",
            "PUT",
            "CONNECT",
            "OPTIONS",
            "TRACE",
            "COPY",
            "LOCK",
            "MKCOL",
            "MOVE",
            "PROPFIND",
            "PROPPATCH",
            "SEARCH",
            "UNLOCK",
            "BIND",
            "REBIND",
            "UNBIND",
            "ACL",
            "REPORT",
            "MKACTIVITY",
            "CHECKOUT",
            "MERGE",
            "MSEARCH",
            "NOTIFY",
            "SUBSCRIBE",
            "UNSUBSCRIBE",
            "PATCH",
            "PURGE",
            "MKCALENDAR",
            "LINK",
            "UNLINK",
            "SOURCE",
            "PRI",
            "DESCRIBE",
            "ANNOUNCE",
            "SETUP",
            "PLAY",
            "PAUSE",
            "TEARDOWN",
            "GET_PARAMETER",
            "SET_PARAMETER",
            "REDIRECT",
            "RECORD",
            "FLUSH",
        ];
        for method in methods {
            let mut expression = String::from("^");
            expression.push_str(method);
            let pattern = hyperscan::Pattern {
                expression,
                id: None,
                flags: hyperscan::PatternFlags::empty(),
                ext: hyperscan::ExprExt::default(),
                som: None,
            };
            let dpi_rule = classifiers::dpi::Rule::new(pattern);
            let mut rule = classifiers::Rule::default();
            rule.rule_type = classifiers::RuleType::DPI(dpi_rule);
            manager.add_rule(&mut rule)?;
        }

        let dpi_rule = classifiers::dpi::Rule::new(pattern! {"^HTTP"});
        let mut rule = classifiers::Rule::default();
        rule.rule_type = classifiers::RuleType::DPI(dpi_rule);
        manager.add_rule(&mut rule)?;

        Ok(())
    }

    fn is_classified(&self) -> bool {
        self.classified
    }

    fn classified_as_this_protocol(&mut self) -> Result<()> {
        self.classified = true;
        Ok(())
    }

    fn parse_pkt(
        &mut self,
        _pkt: &api::packet::Packet,
        ses: &mut api::session::Session,
    ) -> Result<()> {
        if !self.is_classified() {
            // If this session is already classified as this protocol, skip
            self.classified_as_this_protocol()?;
            ses.add_protocol(Box::new(self.name()));
        }

        Ok(())
    }
}

#[no_mangle]
pub fn al_new_protocol_parser() -> Result<Box<dyn api::parsers::ProtocolParser>> {
    Ok(Box::new(ProtocolParser::new()))
}
