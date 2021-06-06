use std::cell::RefCell;
use std::rc::Rc;

use crate::{Md5Context, HTTP};

type Data = Rc<RefCell<HTTP>>;

pub fn on_message_begin(parser: &mut llhttp::Parser) -> libc::c_int {
    let mut http = match parser.data::<Data>() {
        Some(h) => h.borrow_mut(),
        None => return 0,
    };

    http.body_magic.clear();
    http.md5
        .iter_mut()
        .for_each(|md5| *md5 = Md5Context::default());

    0
}

pub fn on_url(parser: &mut llhttp::Parser, at: *const libc::c_char, length: usize) -> libc::c_int {
    let mut http = match parser.data::<Data>() {
        Some(h) => h.borrow_mut(),
        None => return 0,
    };

    let url = unsafe { std::slice::from_raw_parts(at as *const u8, length) };
    http.url.insert(String::from_utf8_lossy(url).to_string());
    0
}

pub fn on_body(parser: &mut llhttp::Parser, at: *const libc::c_char, length: usize) -> libc::c_int {
    let mut http = match parser.data::<Data>() {
        Some(h) => h.borrow_mut(),
        None => return 0,
    };

    let at = at as *const u8;
    let data = unsafe { std::slice::from_raw_parts(at, length) };
    let dir = http.direction as u8 as usize;
    println!("length: {}", length);
    http.md5[dir].as_mut().consume(data);
    0
}

pub fn on_message_complete(parser: &mut llhttp::Parser) -> libc::c_int {
    let mut http = match parser.data::<Data>() {
        Some(h) => h.borrow_mut(),
        None => return 0,
    };
    let dir = http.direction as u8 as usize;
    let d = http.md5[dir].as_mut().clone().compute();
    http.md5_digest.insert(d);
    0
}
