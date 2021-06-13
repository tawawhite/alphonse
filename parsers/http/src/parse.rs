use std::cell::RefMut;
use std::ops::DerefMut;

use anyhow::Result;
use combine::parser::byte::{byte, bytes, space, spaces, take_until_byte, take_until_byte2};
use combine::parser::choice::optional;
use combine::parser::range::{range, take_while1};
use combine::parser::repeat::skip_until;
use combine::parser::Parser;
use combine::{many1, skip_many};

use crate::{Data, Md5Context, State};

#[derive(Clone, Default)]
pub(crate) struct HTTPContext {
    /// Special case for authorization
    auth: Vec<u8>,
    /// Special case for cookie
    cookie: Vec<u8>,
    /// Current HTTP header
    header: Vec<u8>,
    /// Special case for cookie
    host: Vec<u8>,
    /// Current HTTP header's value
    value: Vec<u8>,
    /// Special case for url
    url: Vec<u8>,
}

/// Maybe use nom implement this logic in the future
fn parse_cookie(state: &mut State) -> Result<()> {
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
    let host = take_while1(|b: u8| b != b':');
    let mut host_parser = host.skip(optional(byte(b':')));
    let (host, _) = host_parser.parse(state.ctx.host.as_slice())?;
    let host = String::from_utf8_lossy(host).to_string();
    state.http.host.insert(host);
    Ok(())
}

fn parse_authorization(state: &mut State) -> Result<()> {
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
        .http
        .md5
        .iter_mut()
        .for_each(|md5| *md5 = Md5Context::default());

    Ok(())
}

pub(crate) fn on_url(parser: &mut llhttp::Parser<Data>, data: &[u8]) -> Result<()> {
    let mut state = get_state(parser)?;
    state
        .http
        .uri
        .insert(String::from_utf8_lossy(data).to_string());
    Ok(())
}

pub(crate) fn on_body(parser: &mut llhttp::Parser<Data>, data: &[u8]) -> Result<()> {
    let mut state = get_state(parser)?;

    let dir = state.http.direction as u8 as usize;
    state.http.md5[dir].as_mut().consume(data);
    Ok(())
}

pub(crate) fn on_header_field(parser: &mut llhttp::Parser<Data>, data: &[u8]) -> Result<()> {
    let mut state = get_state(parser)?;
    let http = &mut state.deref_mut().http;

    let header = String::from_utf8_lossy(data).to_string();
    if http.direction == http.client_direction {
        http.request_header.insert(header.clone());
    } else {
        http.response_header.insert(header.clone());
    }

    let ctx = &mut state.deref_mut().ctx;
    ctx.header.extend_from_slice(data);
    ctx.value.clear();

    Ok(())
}

pub(crate) fn on_header_value(parser: &mut llhttp::Parser<Data>, data: &[u8]) -> Result<()> {
    let mut state = get_state(parser)?;
    let state = state.deref_mut();

    let header = String::from_utf8_lossy(state.ctx.header.as_slice()).to_string();
    if state.http.direction == state.http.client_direction {
        state.http.request_header_field.push(header);
    } else {
        state.http.response_header_field.push(header);
    }
    state.ctx.header.clear();

    state.ctx.value.extend_from_slice(data);

    Ok(())
}

pub(crate) fn on_message_complete(parser: &mut llhttp::Parser<Data>) -> Result<()> {
    let mut state = get_state(parser)?;
    let http = &mut state.deref_mut().http;

    let dir = http.direction as u8 as usize;
    let d = http.md5[dir].as_mut().clone().compute();
    http.md5_digest.insert(d);
    Ok(())
}

pub(crate) fn on_headers_complete(parser: &mut llhttp::Parser<Data>) -> Result<()> {
    let mut state = get_state(parser)?;
    let state = state.deref_mut();

    let version = format!("{}.{}", parser.major(), parser.minor());
    if parser.status_code() == 0 {
        state.http.client_version.insert(version);
        state.http.method.insert(parser.method_name().to_string());
    } else {
        state.http.server_version.insert(version);
        state.http.status_code.insert(parser.status_code());
    }

    if state.http.direction == state.http.client_direction {
        parse_host(state)?;
        parse_cookie(state)?;
        parse_authorization(state)?;
    }

    Ok(())
}
