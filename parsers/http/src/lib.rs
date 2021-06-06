use std::cell::RefCell;
use std::collections::HashSet;
use std::rc::Rc;

use anyhow::{anyhow, Result};
use once_cell::sync::OnceCell;
use serde_json::json;

use alphonse_api as api;
use api::classifiers;
use api::classifiers::{dpi, RuleID};
use api::config::Config;
use api::packet::Direction;
use api::plugins::processor::{Processor, ProcessorID};
use api::plugins::{Plugin, PluginType};
use api::session::{ProtocolLayer, Session};

mod parse;
use parse::*;

static SETTINGS: OnceCell<llhttp::Settings> = OnceCell::new();

#[derive(Clone)]
struct HttpProcessor<'a> {
    id: ProcessorID,
    name: String,
    classified: bool,
    parsers: [llhttp::Parser<'a>; 2],
    resp_rule_id: RuleID,
    client_direction: Direction,
}

#[derive(Clone)]
struct Md5Context(md5::Context);

impl Default for Md5Context {
    fn default() -> Self {
        Self(md5::Context::new())
    }
}

impl AsMut<md5::Context> for Md5Context {
    fn as_mut(&mut self) -> &mut md5::Context {
        &mut self.0
    }
}

#[derive(Clone, Default)]
struct HTTP {
    auth: String,
    body_magic: String,
    cookie: String,
    direction: Direction,
    host: String,
    md5: [Md5Context; 2],
    md5_digest: HashSet<md5::Digest>,
    url: HashSet<String>,
    value: [String; 2],
}

unsafe impl Send for HttpProcessor<'_> {}
unsafe impl Sync for HttpProcessor<'_> {}

impl<'a> HttpProcessor<'a> {
    fn new() -> Self {
        HttpProcessor {
            id: 0,
            name: String::from("http"),
            classified: false,
            parsers: [llhttp::Parser::default(), llhttp::Parser::default()],
            resp_rule_id: 0,
            client_direction: Direction::Left,
        }
    }
}

impl<'a> Plugin for HttpProcessor<'static> {
    fn plugin_type(&self) -> PluginType {
        PluginType::PacketProcessor
    }

    fn name(&self) -> &str {
        &self.name.as_str()
    }

    fn init(&self, _: &Config) -> Result<()> {
        // initialize global llhttp settings
        let mut settings = llhttp::Settings::default();

        llhttp::cb_wrapper!(_on_message_begin, on_message_begin);
        settings.on_message_begin(Some(_on_message_begin));

        llhttp::data_cb_wrapper!(_on_url, on_url);
        settings.on_url(Some(_on_url));

        llhttp::data_cb_wrapper!(_on_body, on_body);
        settings.on_body(Some(_on_body));

        llhttp::cb_wrapper!(_on_message_complete, on_message_complete);
        settings.on_message_complete(Some(_on_message_complete));

        SETTINGS.set(settings).unwrap();
        Ok(())
    }
}

impl<'a> Processor for HttpProcessor<'static> {
    fn clone_processor(&self) -> Box<dyn Processor> {
        Box::new(self.clone())
    }

    /// Get parser id
    fn id(&self) -> ProcessorID {
        self.id
    }

    /// Get parser id
    fn set_id(&mut self, id: ProcessorID) {
        self.id = id
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
            manager.add_dpi_rule(self.id(), &pattern, dpi::Protocol::all())?;
        }

        self.resp_rule_id =
            manager.add_simple_dpi_rule(self.id(), "^HTTP", dpi::Protocol::all())?;

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
        pkt: &dyn api::packet::Packet,
        rule: Option<&api::classifiers::matched::Rule>,
        ses: &mut Session,
    ) -> Result<()> {
        let direction = pkt.direction() as u8 as usize;

        // update client direction
        match rule {
            Some(rule) => {
                if rule.id() != self.resp_rule_id {
                    self.client_direction = pkt.direction()
                } else {
                    self.client_direction = pkt.direction().reverse()
                }
            }
            None => {}
        };

        if !self.is_classified() {
            // If this session is already classified as this protocol, skip
            self.classified_as_this_protocol()?;
            ses.add_protocol(&self.name(), ProtocolLayer::All)?;
            ses.add_protocol(&self.name(), ProtocolLayer::Application)?;
            let settings = match SETTINGS.get() {
                Some(s) => s,
                None => return Err(anyhow!("Global llhttp sttings is empty or initializing")),
            };

            let http = Rc::new(RefCell::new(HTTP::default()));
            http.borrow_mut().direction = pkt.direction();
            for parser in &mut self.parsers {
                parser.init(settings, llhttp::Type::HTTP_BOTH);
                parser.set_data(Some(Box::new(http.clone())));
            }
        }

        match self.parsers[direction].parse(pkt.payload()) {
            llhttp::Error::HPE_OK => {}
            llhttp::Error::HPE_PAUSED
            | llhttp::Error::HPE_PAUSED_UPGRADE
            | llhttp::Error::HPE_PAUSED_H2_UPGRADE => {}
            _ => {
                let data = self.parsers[direction].set_data::<Rc<RefCell<HTTP>>>(None);
                let settings = match SETTINGS.get() {
                    Some(s) => s,
                    None => {
                        return Err(anyhow!(
                            "Global llhttp sttings is empty or being initialized"
                        ))
                    }
                };
                self.parsers[direction].init(settings, llhttp::Type::HTTP_BOTH);
                self.parsers[direction].set_data(data);
            }
        };

        Ok(())
    }

    fn finish(&mut self, ses: &mut Session) {
        self.parsers[0].set_data::<Rc<RefCell<HTTP>>>(None);
        let http = self.parsers[1].set_data::<Rc<RefCell<HTTP>>>(None);
        let http = match http {
            None => return,
            Some(http) => http,
        };
        let http = http.borrow();

        // uri
        if !http.url.is_empty() {
            ses.add_field(&"http.uri", &serde_json::json!(http.url));
        }

        // body md5
        let digests: Vec<String> = http
            .md5_digest
            .iter()
            .filter_map(|digest| {
                let s = format!("{:x}", digest);
                if s == "d41d8cd98f00b204e9800998ecf8427e" {
                    None
                } else {
                    Some(s)
                }
            })
            .collect();
        ses.add_field(&"http.md5", &json!(digests));

        println!("{}", serde_json::to_string_pretty(&ses).unwrap());
    }
}

#[no_mangle]
pub extern "C" fn al_new_pkt_processor() -> Box<Box<dyn Processor>> {
    Box::new(Box::new(HttpProcessor::new()))
}

#[no_mangle]
pub extern "C" fn al_plugin_type() -> PluginType {
    PluginType::PacketProcessor
}
