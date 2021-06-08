use std::cell::RefCell;
use std::rc::Rc;

use anyhow::Result;

use crate::{Md5Context, HTTP};

type Data = Rc<RefCell<HTTP>>;

pub fn on_message_begin(parser: &mut llhttp::Parser) -> Result<()> {
    let mut http = match parser.data::<Data>() {
        Some(h) => h.borrow_mut(),
        None => return Ok(()),
    };

    http.body_magic.clear();
    http.md5
        .iter_mut()
        .for_each(|md5| *md5 = Md5Context::default());

    Ok(())
}

pub fn on_url(parser: &mut llhttp::Parser, data: &[u8]) -> Result<()> {
    let mut http = match parser.data::<Data>() {
        Some(h) => h.borrow_mut(),
        None => return Ok(()),
    };

    http.url.insert(String::from_utf8_lossy(data).to_string());
    Ok(())
}

pub fn on_body(parser: &mut llhttp::Parser, data: &[u8]) -> Result<()> {
    let mut http = match parser.data::<Data>() {
        Some(h) => h.borrow_mut(),
        None => return Ok(()),
    };

    let dir = http.direction as u8 as usize;
    http.md5[dir].as_mut().consume(data);
    Ok(())
}

pub fn on_message_complete(parser: &mut llhttp::Parser) -> Result<()> {
    let mut http = match parser.data::<Data>() {
        Some(h) => h.borrow_mut(),
        None => return Ok(()),
    };
    let dir = http.direction as u8 as usize;
    let d = http.md5[dir].as_mut().clone().compute();
    http.md5_digest.insert(d);
    Ok(())
}
