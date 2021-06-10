use std::cell::RefCell;
use std::rc::Rc;

use anyhow::Result;

use crate::{Md5Context, HTTP};

pub(crate) type Data = Rc<RefCell<HTTP>>;

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
            "host" => {
                http.host.insert(value.clone());
            }
            "cookie" => {
                // http.cookies.insert(value.clone(), HashSet::default());
            }
            "authorization" => {}
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
