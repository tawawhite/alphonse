use std::cell::{RefCell, RefMut};
use std::rc::Rc;

use anyhow::Result;
use combine::parser::byte::{byte, bytes, spaces, take_until_byte, take_until_byte2};
use combine::parser::choice::optional;
use combine::parser::range::{range, take_while1};
use combine::parser::repeat::skip_until;
use combine::parser::Parser;
use combine::{many1, skip_many};

use crate::{Md5Context, HTTP};

pub(crate) type Data = Rc<RefCell<HTTP>>;

/// Maybe use nom implement this logic in the future
fn parse_cookie(data: &[u8], http: &mut RefMut<HTTP>) -> Result<()> {
    let key = take_until_byte(b'=');
    let value = take_while1(|b| b != b';');
    let kv_parser = key
        .skip(byte(b'='))
        .and(value)
        .skip(optional(byte(b';')))
        .skip(optional(spaces()));
    let mut cookie_parser = many1::<Vec<(&[u8], &[u8])>, _, _>(kv_parser);

    let kvs = cookie_parser.parse(data)?.0;
    for (k, v) in kvs.iter() {
        http.cookie_key
            .insert(String::from_utf8_lossy(k).to_string());
        http.cookie_value
            .insert(String::from_utf8_lossy(v).to_string());
    }
    Ok(())
}

fn parse_host(data: &[u8], http: &mut RefMut<HTTP>) -> Result<()> {
    let host = take_while1(|b: u8| b != b':');
    let mut host_parser = host.skip(optional(byte(b':')));
    let (host, _) = host_parser.parse(data)?;
    let host = String::from_utf8_lossy(host).to_string();
    http.host.insert(host);
    Ok(())
}

fn parse_authorization(data: &[u8], http: &mut RefMut<HTTP>) -> Result<()> {
    let auth_type = take_until_byte(b' ');
    let mut auth_parser = skip_many(spaces()).and(auth_type).skip(spaces());
    let ((_, auth), value) = auth_parser.parse(data)?;

    let auth_type = String::from_utf8_lossy(auth).to_string();
    http.auth_type.insert(auth_type);

    match auth.to_ascii_lowercase().as_slice() {
        b"basic" => {
            let mut basic_parser = range(&b"token="[..]).and(take_until_byte(b':'));
            let ((_, user), _) = basic_parser.parse(value)?;
            let user = String::from_utf8_lossy(user).to_string();
            http.user.insert(user);
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
            http.user.insert(user);
        }
        _ => {}
    };

    Ok(())
}

pub(crate) fn on_message_begin(parser: &mut llhttp::Parser<Data>) -> Result<()> {
    let mut http = match parser.data() {
        Some(h) => h.borrow_mut(),
        None => return Ok(()),
    };

    http.body_magic.clear();
    http.md5
        .iter_mut()
        .for_each(|md5| *md5 = Md5Context::default());

    Ok(())
}

pub(crate) fn on_url(parser: &mut llhttp::Parser<Data>, data: &[u8]) -> Result<()> {
    let mut http = match parser.data() {
        Some(h) => h.borrow_mut(),
        None => return Ok(()),
    };

    http.uri.insert(String::from_utf8_lossy(data).to_string());
    Ok(())
}

pub(crate) fn on_body(parser: &mut llhttp::Parser<Data>, data: &[u8]) -> Result<()> {
    let mut http = match parser.data() {
        Some(h) => h.borrow_mut(),
        None => return Ok(()),
    };

    let dir = http.direction as u8 as usize;
    http.md5[dir].as_mut().consume(data);
    Ok(())
}

pub(crate) fn on_header_field(parser: &mut llhttp::Parser<Data>, data: &[u8]) -> Result<()> {
    let mut http = match parser.data() {
        Some(h) => h.borrow_mut(),
        None => return Ok(()),
    };

    let header = String::from_utf8_lossy(data).to_string();
    if http.direction == http.client_direction {
        http.request_header.insert(header.clone());
        http.request_header_field.push(header.clone());
    } else {
        http.response_header.insert(header.clone());
        http.response_header_field.push(header.clone());
    }

    http.last_header = header;

    Ok(())
}

pub(crate) fn on_header_value(parser: &mut llhttp::Parser<Data>, data: &[u8]) -> Result<()> {
    let mut http = match parser.data() {
        Some(h) => h.borrow_mut(),
        None => return Ok(()),
    };

    let value = String::from_utf8_lossy(data).to_string();
    if http.direction == http.client_direction {
        http.request_header_field.push(value.clone());
        match http.last_header.to_ascii_lowercase().as_str() {
            "host" => parse_host(data, &mut http)?,
            "cookie" => parse_cookie(data, &mut http)?,
            "authorization" => parse_authorization(data, &mut http)?,
            _ => {}
        }
    } else {
        http.response_header_field.push(value.clone());
    }

    Ok(())
}

pub(crate) fn on_message_complete(parser: &mut llhttp::Parser<Data>) -> Result<()> {
    let mut http = match parser.data() {
        Some(h) => h.borrow_mut(),
        None => return Ok(()),
    };
    let dir = http.direction as u8 as usize;
    let d = http.md5[dir].as_mut().clone().compute();
    http.md5_digest.insert(d);
    Ok(())
}

pub(crate) fn on_headers_complete(parser: &mut llhttp::Parser<Data>) -> Result<()> {
    let mut http = match parser.data() {
        Some(h) => h.borrow_mut(),
        None => return Ok(()),
    };
    let version = format!("{}.{}", parser.major(), parser.minor());
    if parser.status_code() == 0 {
        http.client_version.insert(version);
        http.method.insert(parser.method_name().to_string());
    } else {
        http.server_version.insert(version);
        http.status_code.insert(parser.status_code());
    }
    Ok(())
}
