#[derive(Debug)]
pub enum Error {
    CaptureError(String),
    ParserError(String),
    CommonError(String),
}

impl Error {
    pub fn new(msg: &str) -> Error {
        Error::CommonError(String::from(""))
    }
}
