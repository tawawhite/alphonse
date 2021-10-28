use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use once_cell::sync::OnceCell;
use serde::Serialize;
use serde_json::json;

use alphonse_api as api;
use alphonse_utils as utils;
use api::classifiers;
use api::classifiers::{dpi, matched::Rule, RuleID};
use api::config::Config;
use api::packet::{Direction, Packet, Protocol};
use api::plugins::processor::{
    Builder as ProcessorBuilder, Processor as PktProcessor, ProcessorID,
};
use api::plugins::{Plugin, PluginType};
use api::session::{ProtocolLayer, Session};
use utils::tcp_reassembly::TcpReorder;

mod parse;
use parse::*;

static SETTINGS: OnceCell<llhttp::Settings> = OnceCell::new();
static PARSE_CFG: OnceCell<Arc<ParseConfig>> = OnceCell::new();

#[derive(Clone, Default)]
struct State {
    http: HTTP,
    ctx: HTTPContext,
    cfg: Arc<ParseConfig>,
}

type Data = Rc<RefCell<State>>;

#[derive(Clone, Debug, Default, Serialize)]
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

#[derive(Clone, Debug, Default)]
struct Builder {
    id: ProcessorID,
    resp_rule_id: RuleID,
}

impl ProcessorBuilder for Builder {
    fn build(&self, _: &Config) -> Box<dyn PktProcessor> {
        let mut p = Box::new(HttpProcessor::default());
        p.tcp_reorder = [TcpReorder::with_capacity(16), TcpReorder::with_capacity(16)];
        p
    }

    fn id(&self) -> ProcessorID {
        self.id
    }

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
}

impl Plugin for Builder {
    fn plugin_type(&self) -> PluginType {
        PluginType::PacketProcessor
    }

    fn name(&self) -> &str {
        &"http"
    }

    fn init(&mut self, cfg: &Config) -> Result<()> {
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

        let mut parse_config = ParseConfig::default();
        parse_config.parse_qs_value = cfg.get_boolean("http.parseQSValue", false);
        parse_config.parse_cookie_value = cfg.get_boolean("http.parseCookieValue", false);
        parse_config.parse_all_request_headers =
            cfg.get_boolean("http.parseHTTPHeaderRequestAll", false);
        parse_config.parse_all_response_headers =
            cfg.get_boolean("http.parseHTTPHeaderResponseAll", false);

        parse_config.headers = cfg.get_str_arr("http.headers").into_iter().collect();
        parse_config.req_headers = cfg
            .get_str_arr("http.request.headers")
            .into_iter()
            .collect();
        parse_config.resp_headers = cfg
            .get_str_arr("http.response.headers")
            .into_iter()
            .collect();

        PARSE_CFG.set(Arc::new(parse_config)).or(Err(anyhow!(
            "http pkt parser's PARSE_CFG is already setted"
        )))?;

        Ok(())
    }
}

#[derive(Clone, Default)]
struct HttpProcessor<'a> {
    id: ProcessorID,
    classified: bool,
    parsers: [llhttp::Parser<'a, Data>; 2],
    tcp_reorder: [TcpReorder; 2],
    resp_rule_id: RuleID,
    client_direction: Direction,
}

unsafe impl Send for HttpProcessor<'_> {}
unsafe impl Sync for HttpProcessor<'_> {}

impl<'a> PktProcessor for HttpProcessor<'static> {
    fn id(&self) -> ProcessorID {
        self.id
    }

    fn name(&self) -> &'static str {
        &"http"
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
            s.cfg = match PARSE_CFG.get() {
                None => unreachable!("this should never happends"),
                Some(cfg) => cfg.clone(),
            };
            for parser in &mut self.parsers {
                parser.init(settings, llhttp::Type::HTTP_BOTH);
                parser.set_data(Some(Box::new(state.clone())));
            }
        }

        match pkt.layers().transport() {
            None => unreachable!("http processor received a pkt with no transport layer"),
            Some(l) => {
                if l.protocol != Protocol::TCP {
                    match self.process_pkt(pkt) {
                        Ok(_) => {}
                        Err(e) => eprintln!("{}", e),
                    };
                    return Ok(());
                }
            }
        }

        if self.tcp_reorder[direction].full() {
            for pkt in self.tcp_reorder[direction].get_interval_pkts() {
                match self.process_pkt(pkt.as_ref()) {
                    Ok(_) => {}
                    Err(e) => eprintln!("{}", e),
                };
            }
        }

        self.tcp_reorder[direction].insert_and_reorder(pkt.clone_box());

        Ok(())
    }

    fn mid_save(&mut self, ses: &mut api::session::Session) {
        for pkt in self.tcp_reorder[0].get_all_pkts() {
            match self.process_pkt(pkt.as_ref()) {
                Ok(_) => {}
                Err(e) => eprintln!("{}", e),
            };
        }
        for pkt in self.tcp_reorder[1].get_all_pkts() {
            match self.process_pkt(pkt.as_ref()) {
                Ok(_) => {}
                Err(e) => eprintln!("{}", e),
            };
        }

        ses.add_protocol(&self.name(), ProtocolLayer::Application);
        let state = match self.parsers[0].data() {
            None => return,
            Some(s) => s.borrow(),
        };
        ses.add_field(&"http", json!(state.http));
    }

    fn save(&mut self, ses: &mut Session) {
        for parser in &mut self.parsers {
            parser.finish();
        }
        self.mid_save(ses);
        self.parsers[0].set_data(None);
        self.parsers[1].set_data(None);
    }
}

impl<'a> HttpProcessor<'a> {
    /// Process reassembled TCP pkts or UDP/SCTP pkts
    fn process_pkt(&mut self, pkt: &dyn Packet) -> Result<()> {
        let direction = pkt.direction() as u8 as usize;

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
}

#[no_mangle]
pub extern "C" fn al_new_pkt_processor_builder() -> Box<Box<dyn ProcessorBuilder>> {
    Box::new(Box::new(Builder::default()))
}

#[no_mangle]
pub extern "C" fn al_plugin_type() -> PluginType {
    PluginType::PacketProcessor
}
