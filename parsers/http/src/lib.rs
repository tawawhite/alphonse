use std::cell::RefCell;
use std::collections::HashSet;
use std::rc::Rc;

use anyhow::{anyhow, Result};
use once_cell::sync::OnceCell;
use serde::Serialize;
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
    parsers: [llhttp::Parser<'a, Rc<RefCell<HTTP>>>; 2],
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

#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct HTTP {
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    auth_type: HashSet<String>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    body_magic: HashSet<String>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    client_version: HashSet<String>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    server_version: HashSet<String>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    cookie_key: HashSet<String>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    cookie_value: HashSet<String>,
    #[serde(skip_serializing)]
    client_direction: Direction,
    #[serde(skip_serializing)]
    direction: Direction,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    host: HashSet<String>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    key: HashSet<String>,
    #[serde(skip_serializing)]
    last_header: String,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    method: HashSet<String>,
    #[serde(skip_serializing)]
    md5: [Md5Context; 2],
    #[serde(skip_serializing)]
    md5_digest: HashSet<md5::Digest>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    path: HashSet<String>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    request_body: HashSet<String>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    request_header: HashSet<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    request_header_field: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    request_header_value: Vec<String>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    response_header: HashSet<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    response_header_field: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    response_header_value: Vec<String>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    status_code: HashSet<u16>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    uri: HashSet<String>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    user: HashSet<String>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    user_agent: HashSet<String>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    value: HashSet<String>,
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

        llhttp::cb_wrapper!(_on_message_begin, on_message_begin, Data);
        settings.on_message_begin(Some(_on_message_begin));

        llhttp::data_cb_wrapper!(_on_url, on_url, Data);
        settings.on_url(Some(_on_url));

        llhttp::data_cb_wrapper!(_on_header_field, on_header_field, Data);
        settings.on_header_field(Some(_on_header_field));

        llhttp::data_cb_wrapper!(_on_header_value, on_header_value, Data);
        settings.on_header_value(Some(_on_header_value));

        llhttp::cb_wrapper!(_on_header_complete, on_headers_complete, Data);
        settings.on_headers_complete(Some(_on_header_complete));

        llhttp::data_cb_wrapper!(_on_body, on_body, Data);
        settings.on_body(Some(_on_body));

        llhttp::cb_wrapper!(_on_message_complete, on_message_complete, Data);
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
            let mut h = http.borrow_mut();
            h.direction = pkt.direction();
            h.client_direction = self.client_direction;
            for parser in &mut self.parsers {
                parser.init(settings, llhttp::Type::HTTP_BOTH);
                parser.set_data(Some(Box::new(http.clone())));
            }
        }

        match self.parsers[direction].data() {
            None => {}
            Some(http) => http.borrow_mut().direction = pkt.direction(),
        };

        match self.parsers[direction].parse(pkt.payload()) {
            llhttp::Error::HPE_OK => {}
            llhttp::Error::HPE_PAUSED
            | llhttp::Error::HPE_PAUSED_UPGRADE
            | llhttp::Error::HPE_PAUSED_H2_UPGRADE => {}
            _ => {
                let data = self.parsers[direction].set_data(None);
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
        self.parsers[0].set_data(None);
        let http = self.parsers[1].set_data(None);
        let http = match http {
            None => return,
            Some(http) => http,
        };
        ses.add_field(&"http", json!(http));

        // body md5
        // let digests: Vec<String> = http
        //     .md5_digest
        //     .iter()
        //     .filter_map(|digest| {
        //         let s = format!("{:x}", digest);
        //         if s == "d41d8cd98f00b204e9800998ecf8427e" {
        //             None
        //         } else {
        //             Some(s)
        //         }
        //     })
        //     .collect();
        // ses.add_field(&"http.md5", &json!(digests));

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
