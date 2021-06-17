use std::borrow::Borrow;
use std::cell::RefMut;
use std::collections::HashSet;
use std::ops::DerefMut;
use std::sync::{Arc, RwLock};

use anyhow::{anyhow, Result};
use combine::parser::byte::{byte, bytes, space, spaces, take_until_byte, take_until_byte2};
use combine::parser::choice::optional;
use combine::parser::range::{range, take_while1};
use combine::parser::repeat::skip_until;
use combine::parser::Parser;
use combine::{many1, skip_many};
use percent_encoding::percent_decode_str;
use url::Url;

use alphonse_api as api;
use api::packet::Direction;

use crate::{Data, State};

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
pub(crate) struct HTTPContext {
    /// Special case for authorization
    auth: Vec<u8>,
    /// Client Direction
    pub client_direction: Direction,
    /// Special case for cookie
    cookie: Vec<u8>,
    /// Current HTTP Direction
    pub direction: Direction,
    /// Current HTTP header
    header: Vec<u8>,
    /// Headers to be added
    pub headers: Arc<RwLock<HashSet<String>>>,
    /// Special case for cookie
    host: Vec<u8>,
    /// Body Md5
    md5: [Md5Context; 2],
    /// Request headers to be added
    pub req_headers: Arc<RwLock<HashSet<String>>>,
    /// Response headers to be added
    pub resp_headers: Arc<RwLock<HashSet<String>>>,
    /// Current HTTP header's value
    value: Vec<u8>,
    /// Special case for url
    url: Vec<u8>,
}

impl HTTPContext {
    /// Decide whether a header should be saved
    fn find_header(&self, header: &str) -> Result<Vec<String>> {
        let mut headers = vec![];
        match self
            .headers
            .read()
            .or_else(|e| Err(anyhow!("{}", e)))?
            .get(header)
        {
            Some(_) => headers.push(header.to_string()),
            None => {}
        };

        match self
            .req_headers
            .read()
            .or_else(|e| Err(anyhow!("{}", e)))?
            .get(header)
        {
            Some(_) => headers.push(format!("request-{}", header)),
            None => {}
        };

        match self
            .resp_headers
            .read()
            .or_else(|e| Err(anyhow!("{}", e)))?
            .get(&format!("response-{}", header))
        {
            Some(_) => headers.push(format!("response-{}", header)),
            None => {}
        }
        Ok(headers)
    }
}

/// Maybe use nom implement this logic in the future
fn parse_cookie(state: &mut State) -> Result<()> {
    if state.ctx.cookie.is_empty() {
        return Ok(());
    };

    let key = take_until_byte(b'=');
    let value = take_while1(|b| b != b';');
    let kv_parser = key
        .skip(byte(b'='))
        .and(value)
        .skip(optional(byte(b';')))
        .skip(optional(spaces()));
    let mut cookie_parser = many1::<Vec<(&[u8], &[u8])>, _, _>(kv_parser);

    let kvs = cookie_parser.parse(state.ctx.cookie.as_slice())?.0;
    for (k, v) in kvs.iter() {
        state
            .http
            .cookie_key
            .insert(String::from_utf8_lossy(k).to_string());
        state
            .http
            .cookie_value
            .insert(String::from_utf8_lossy(v).to_string());
    }
    Ok(())
}

fn parse_host(state: &mut State) -> Result<()> {
    if state.ctx.host.is_empty() {
        return Ok(());
    };

    let host = take_while1(|b: u8| b != b':');
    let mut host_parser = host.skip(optional(byte(b':')));
    let (host, _) = host_parser.parse(state.ctx.host.as_slice())?;
    let host = String::from_utf8_lossy(host).to_string();
    state.http.host.insert(host);
    Ok(())
}

fn parse_authorization(state: &mut State) -> Result<()> {
    if state.ctx.auth.is_empty() {
        return Ok(());
    };
    let auth_type = take_until_byte(b' ');
    let mut auth_parser = skip_many(space()).and(auth_type).skip(spaces());
    let ((_, auth), value) = auth_parser.parse(state.ctx.auth.as_slice())?;

    let auth_type = String::from_utf8_lossy(auth).to_string();
    state.http.auth_type.insert(auth_type);

    match auth.to_ascii_lowercase().as_slice() {
        b"basic" => {
            let mut basic_parser = range(&b"token="[..]).and(take_until_byte(b':'));
            let ((_, user), _) = basic_parser.parse(value)?;
            let user = String::from_utf8_lossy(user).to_string();
            state.http.user.insert(user);
        }
        b"digest" => {
            let mut parser = skip_until(bytes(b"username"))
                .skip(spaces())
                .skip(byte(b'='))
                .skip(spaces())
                .skip(optional(byte(b'"')))
                .and(take_until_byte2(b'"', b','));
            let ((_, user), _) = parser.parse(value)?;
            let user = String::from_utf8_lossy(user).to_string();
            state.http.user.insert(user);
        }
        _ => {}
    };

    Ok(())
}

fn parse_url(state: &mut State) -> Result<()> {
    // construct a valid url for Url to parse, mey rewrite in combine in the future
    let mut url = vec![];
    url.extend(b"http://".iter());
    url.extend(state.ctx.host.iter());
    url.extend(state.ctx.url.iter());

    let url = Url::parse(std::str::from_utf8(url.as_slice())?)?;
    state.http.path.insert(url.path().to_string());
    for (key, value) in url.query_pairs() {
        let key = match percent_decode_str(key.borrow()).decode_utf8() {
            Ok(k) => k,
            Err(_) => key,
        };
        state.http.key.insert(key.to_string());
        let value = match percent_decode_str(value.borrow()).decode_utf8() {
            Ok(v) => v,
            Err(_) => value,
        };
        state.http.value.insert(value.to_string());
    }

    Ok(())
}

#[inline]
fn get_state<'a>(parser: &'a llhttp::Parser<Data>) -> Result<RefMut<'a, State>> {
    match parser.data() {
        Some(h) => Ok(h.borrow_mut()),
        None => unreachable!(),
    }
}

pub(crate) fn on_message_begin(parser: &mut llhttp::Parser<Data>) -> Result<()> {
    let mut state = get_state(parser)?;

    state.http.body_magic.clear();
    state
        .ctx
        .md5
        .iter_mut()
        .for_each(|md5| *md5 = Md5Context::default());

    Ok(())
}

pub(crate) fn on_url(parser: &mut llhttp::Parser<Data>, data: &[u8]) -> Result<()> {
    let mut state = get_state(parser)?;
    state.ctx.url.extend_from_slice(data);
    Ok(())
}

pub(crate) fn on_body(parser: &mut llhttp::Parser<Data>, data: &[u8]) -> Result<()> {
    let mut state = get_state(parser)?;

    let dir = state.ctx.direction as u8 as usize;
    state.ctx.md5[dir].as_mut().consume(data);
    Ok(())
}

fn save_header_value(state: &mut State) -> Result<()> {
    if !state.ctx.value.is_empty() {
        // if value is not empty, add it to header's values
        let header = state.ctx.header.to_ascii_lowercase();
        let header = String::from_utf8_lossy(header.as_slice()).to_string();
        let headers = state.ctx.find_header(header.as_str())?;
        let value = String::from_utf8_lossy(state.ctx.value.as_slice()).to_string();

        for header in headers {
            let value = value.clone();
            match state.http.header_values.get_mut(&header) {
                Some(values) => {
                    values.insert(value);
                }
                None => {
                    let mut values = HashSet::default();
                    values.insert(value);
                    state.http.header_values.insert(header.clone(), values);
                }
            };
        }
        if state.ctx.direction == state.ctx.client_direction {
            state.http.request_header_value.push(value);
        } else {
            state.http.response_header_value.push(value);
        }
        state.ctx.value.clear();
    }
    Ok(())
}

pub(crate) fn on_header_field(parser: &mut llhttp::Parser<Data>, data: &[u8]) -> Result<()> {
    let mut state = get_state(parser)?;

    save_header_value(state.deref_mut())?;

    state.ctx.header.clear();
    state.ctx.header.extend_from_slice(data);

    Ok(())
}

pub(crate) fn on_header_value(parser: &mut llhttp::Parser<Data>, data: &[u8]) -> Result<()> {
    let mut state = get_state(parser)?;

    let header = String::from_utf8_lossy(state.ctx.header.as_slice()).to_string();
    let hdr_low = header.to_ascii_lowercase();

    match hdr_low.as_str() {
        "authorization" => state.ctx.auth.extend_from_slice(data),
        "cookie" => state.ctx.cookie.extend_from_slice(data),
        "host" => state.ctx.host.extend_from_slice(data),
        _ => {}
    };

    let headers = state.ctx.find_header(hdr_low.as_str())?;
    if headers.len() > 0 {
        state.ctx.value.extend_from_slice(data);
    }

    for header in headers {
        match state.http.header_values.get_mut(&header) {
            None => {
                state
                    .http
                    .header_values
                    .insert(header.clone(), HashSet::default());
            }
            Some(_) => {}
        };
    }

    if state.ctx.direction == state.ctx.client_direction {
        state.http.request_header_field.push(header.clone());
        state.http.request_header.insert(header);
    } else {
        state.http.response_header_field.push(header.clone());
        state.http.response_header.insert(header);
    }

    Ok(())
}

pub(crate) fn on_message_complete(parser: &mut llhttp::Parser<Data>) -> Result<()> {
    let mut state = get_state(parser)?;

    let dir = state.ctx.direction as u8 as usize;
    let digest = state.ctx.md5[dir].as_mut().clone().compute();

    let digest = format!("{:x}", digest);
    if digest != "d41d8cd98f00b204e9800998ecf8427e" {
        state.http.md5.insert(digest);
    }

    Ok(())
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

pub(crate) fn on_headers_complete(parser: &mut llhttp::Parser<Data>) -> Result<()> {
    let mut state = get_state(parser)?;

    let version = format!("{}.{}", parser.major(), parser.minor());
    if parser.status_code() == 0 {
        state.http.client_version.insert(version);
        state.http.method.insert(parser.method_name().to_string());
    } else {
        state.http.server_version.insert(version);
        state.http.status_code.insert(parser.status_code());
    }

    if !state.ctx.url.is_empty() && state.ctx.direction == state.ctx.client_direction {
        match parse_url(state.deref_mut()) {
            Err(e) => eprintln!("{}", e),
            Ok(_) => {}
        }
        let url = if state.ctx.url[0] == b'/' {
            let mut url = state.ctx.host.clone();
            url.extend(state.ctx.url.iter());
            url
        } else {
            match find_subsequence(state.ctx.url.as_slice(), state.ctx.host.as_slice()) {
                Some(_) => {
                    if state.ctx.host.len() <= 8 {
                        state.ctx.url.clone()
                    } else {
                        let mut url = state.ctx.host.clone();
                        url.push(b';');
                        url.extend(state.ctx.url.iter());
                        url
                    }
                }
                None => {
                    let mut url = state.ctx.host.clone();
                    url.push(b';');
                    url.extend(state.ctx.url.iter());
                    url
                }
            }
        };
        state
            .http
            .uri
            .insert(String::from_utf8_lossy(url.as_slice()).to_string());
    }

    save_header_value(state.deref_mut())
        .unwrap_or_else(|e| eprintln!("save header value failed: {}", e));
    parse_authorization(state.deref_mut())
        .unwrap_or_else(|e| eprintln!("parse authorization failed: {}", e));
    parse_cookie(state.deref_mut()).unwrap_or_else(|e| eprintln!("parse cookie failed: {}", e));
    parse_host(state.deref_mut()).unwrap_or_else(|e| eprintln!("parse host failed: {}", e));

    state.ctx.url.clear();
    state.ctx.host.clear();
    state.ctx.cookie.clear();
    state.ctx.auth.clear();

    Ok(())
}
