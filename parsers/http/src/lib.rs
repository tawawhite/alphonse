#[macro_use]
extern crate lazy_static;

use anyhow::{anyhow, Result};
use hyperscan::pattern;

use alphonse_api as api;
use api::classifiers;
use api::classifiers::dpi;
use api::parsers::ParserID;
use api::session::Session;

lazy_static! {
    static ref SETTINGS: llhttp::Settings = {
        let mut settings = llhttp::Settings::default();
        llhttp::data_cb_wrapper!(_on_url, on_url);
        settings.on_url(Some(_on_url));
        settings
    };
}

#[derive(Clone)]
struct ProtocolParser<'a> {
    id: ParserID,
    name: String,
    classified: bool,
    parsers: [llhttp::Parser<'a>; 2],
}

fn on_url(parser: &mut llhttp::Parser, at: *const libc::c_char, length: usize) -> libc::c_int {
    let http = if parser.data().is_null() {
        println!("null ptr for llhttp parser");
        return 0;
    } else {
        unsafe { &mut *(parser.data() as *mut HTTP) }
    };

    if http.url.is_empty() {
        let url = unsafe { std::slice::from_raw_parts(at as *const u8, length) };
        http.url = String::from_utf8_lossy(url).to_string();
    } else {
        let url = unsafe { std::slice::from_raw_parts(at as *const u8, length) };
        let url = String::from_utf8_lossy(url).to_string();
        http.url.extend(url.chars());
    }
    0
}

#[derive(Clone, Default)]
struct HTTP {
    url: String,
    host: String,
    cookie: String,
    auth: String,
    value: [String; 2],
    header: [String; 2],
    checksum: String,
}

unsafe impl Send for ProtocolParser<'_> {}
unsafe impl Sync for ProtocolParser<'_> {}

impl<'a> ProtocolParser<'a> {
    fn new() -> Self {
        let mut parser = ProtocolParser {
            id: 0,
            name: String::from("http"),
            classified: false,
            parsers: [llhttp::Parser::default(), llhttp::Parser::default()],
        };
        parser.parsers[0].init(&SETTINGS, llhttp::Type::BOTH);
        parser.parsers[1].init(&SETTINGS, llhttp::Type::BOTH);
        parser
    }
}

impl<'a> api::parsers::ProtocolParserTrait for ProtocolParser<'static> {
    fn box_clone(&self) -> Box<dyn api::parsers::ProtocolParserTrait> {
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
    fn name(&self) -> &str {
        &self.name.as_str()
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
            let dpi_rule = dpi::Rule::new(pattern);
            let mut rule = classifiers::Rule::new(self.id());
            rule.rule_type = classifiers::RuleType::DPI(dpi_rule);
            manager.add_rule(&mut rule)?;
        }

        let dpi_rule = classifiers::dpi::Rule::new(pattern! {"^HTTP"});
        let mut rule = classifiers::Rule::new(self.id());
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
        pkt: &Box<dyn api::packet::Packet>,
        _rule: Option<&api::classifiers::matched::Rule>,
        ses: &mut Session,
    ) -> Result<()> {
        if !self.is_classified() {
            // If this session is already classified as this protocol, skip
            self.classified_as_this_protocol()?;
            ses.add_protocol(self.name());
            self.parsers[0].init(&SETTINGS, llhttp::Type::BOTH);
            self.parsers[1].init(&SETTINGS, llhttp::Type::BOTH);
            let http = Box::new(HTTP::default());
            let http = Box::into_raw(http) as *mut libc::c_void;
            self.parsers[0].set_data(http);
            self.parsers[1].set_data(http);
        }

        let direction = pkt.direction() as u8 as usize;
        match self.parsers[direction].parse(pkt.payload()) {
            llhttp::Error::Ok => {}
            llhttp::Error::Paused | llhttp::Error::PausedUpgrade => {}
            _ => {
                let data = self.parsers[direction].data();
                self.parsers[direction].init(&SETTINGS, llhttp::Type::BOTH);
                self.parsers[direction].set_data(data);
            }
        };

        Ok(())
    }

    fn finish(&mut self, ses: &mut Session) {
        let data = self.parsers[0].set_data(std::ptr::null_mut());
        let http = unsafe { Box::from_raw(data as *mut HTTP) };
        self.parsers[1].set_data(std::ptr::null_mut());
        ses.add_field(&"http.uri", &serde_json::json!(http.url));
    }
}

#[no_mangle]
pub extern "C" fn al_new_protocol_parser() -> Box<Box<dyn api::parsers::ProtocolParserTrait>> {
    Box::new(Box::new(ProtocolParser::new()))
}
