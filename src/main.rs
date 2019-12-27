#[macro_use]
extern crate clap;

mod commands;
mod config;

fn main() {
    let root_cmd = commands::new_root_command();

    let _config = config::parse_args(root_cmd);

    println!("Hello, world!");
}
