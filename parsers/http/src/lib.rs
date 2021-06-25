use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::ops::DerefMut;
use std::rc::Rc;
use std::sync::{Arc, RwLock};

use anyhow::{anyhow, Result};
use once_cell::sync::OnceCell;
use serde::Serialize;
use serde_json::json;

use alphonse_api as api;
use api::classifiers;
use api::classifiers::{dpi, matched::Rule, RuleID};
use api::config::Config;
use api::packet::{Direction, Packet};
use api::plugins::processor::{Processor, ProcessorID};
use api::plugins::{Plugin, PluginType};
use api::session::{ProtocolLayer, Session};

mod parse;
use parse::*;

static SETTINGS: OnceCell<llhttp::Settings> = OnceCell::new();

#[derive(Clone, Default)]
struct State {
    http: HTTP,
    ctx: HTTPContext,
}

type Data = Rc<RefCell<State>>;

#[derive(Clone)]
struct HttpProcessor<'a> {
    id: ProcessorID,
    name: String,
    classified: bool,
    parsers: [llhttp::Parser<'a, Data>; 2],
    resp_rule_id: RuleID,
    client_direction: Direction,
    headers: Arc<RwLock<HashSet<String>>>,
    req_headers: Arc<RwLock<HashSet<String>>>,
    resp_headers: Arc<RwLock<HashSet<String>>>,
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
    cookie_key: HashSet<String>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    cookie_value: HashSet<String>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    #[serde(flatten)]
    header_values: HashMap<String, HashSet<String>>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    host: HashSet<String>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    key: HashSet<String>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    method: HashSet<String>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    md5: HashSet<String>,
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
    server_version: HashSet<String>,
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
            headers: Arc::default(),
            req_headers: Arc::default(),
            resp_headers: Arc::default(),
        }
    }
}

impl<'a> Plugin for HttpProcessor<'a> {
    fn plugin_type(&self) -> PluginType {
        PluginType::PacketProcessor
    }

    fn name(&self) -> &str {
        &self.name.as_str()
    }

    fn init(&self, cfg: &Config) -> Result<()> {
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

        let headers = cfg.get_str_arr("http.headers");
        let mut hdrs = self.headers.write().or_else(|e| Err(anyhow!("{}", e)))?;
        *hdrs = headers.into_iter().collect();

        let headers = cfg.get_str_arr("http.request.headers");
        let mut req_headers = self
            .req_headers
            .write()
            .or_else(|e| Err(anyhow!("{}", e)))?;
        let req_headers = req_headers.deref_mut();
        *req_headers = headers.into_iter().collect();

        let headers = cfg.get_str_arr("http.response.headers");
        let mut resp_headers = self
            .resp_headers
            .write()
            .or_else(|e| Err(anyhow!("{}", e)))?;
        let resp_headers = resp_headers.deref_mut();
        *resp_headers = headers.into_iter().collect();

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

    fn parse_pkt(&mut self, pkt: &dyn Packet, rule: Option<&Rule>, _: &mut Session) -> Result<()> {
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

        if !self.classified {
            // If this session is already classified as this protocol, skip
            self.classified = true;
            let settings = match SETTINGS.get() {
                Some(s) => s,
                None => return Err(anyhow!("Global llhttp sttings is empty or initializing")),
            };

            let state = Rc::new(RefCell::new(State::default()));
            let mut s = state.borrow_mut();
            s.ctx.direction = pkt.direction();
            s.ctx.client_direction = self.client_direction;
            s.ctx.headers = self.headers.clone();
            s.ctx.req_headers = self.req_headers.clone();
            s.ctx.resp_headers = self.resp_headers.clone();
            for parser in &mut self.parsers {
                parser.init(settings, llhttp::Type::HTTP_BOTH);
                parser.set_data(Some(Box::new(state.clone())));
            }
        }

        match self.parsers[direction].data() {
            None => {}
            Some(s) => s.borrow_mut().ctx.direction = pkt.direction(),
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

    fn mid_save(&mut self, ses: &mut api::session::Session) {
        ses.add_protocol(&self.name(), ProtocolLayer::Application);
        let state = match self.parsers[0].data() {
            None => return,
            Some(s) => s.borrow(),
        };
        ses.add_field(&"http", json!(state.http));
        println!("{}", serde_json::to_string_pretty(&ses).unwrap());
    }

    fn save(&mut self, ses: &mut Session) {
        for parser in &mut self.parsers {
            parser.finish();
        }
        self.mid_save(ses);
    }

    fn finish(&mut self) -> Result<()> {
        self.parsers[0].set_data(None);
        self.parsers[1].set_data(None);
        Ok(())
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
