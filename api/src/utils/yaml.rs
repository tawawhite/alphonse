#[derive(Clone, Debug)]
/// Simple wrapper struct to implement Default trait for toml::Value
pub struct Yaml(pub yaml_rust::Yaml);

impl Default for Yaml {
    fn default() -> Self {
        Self(yaml_rust::Yaml::Null)
    }
}

impl AsRef<yaml_rust::Yaml> for Yaml {
    fn as_ref(&self) -> &yaml_rust::Yaml {
        &self.0
    }
}

impl AsMut<yaml_rust::Yaml> for Yaml {
    fn as_mut(&mut self) -> &mut yaml_rust::Yaml {
        &mut self.0
    }
}

pub fn get_str(doc: &yaml_rust::Yaml, key: &str, default: &str) -> String {
    match &doc[key] {
        yaml_rust::Yaml::String(s) => s.clone(),
        yaml_rust::Yaml::BadValue => {
            println!(
                "Option {} not found or bad string value, set {} to {}",
                key, key, default
            );
            default.to_string()
        }
        _ => {
            println!(
                "Wrong value type for {}, expecting string, set {} to {}",
                key, key, default
            );
            default.to_string()
        }
    }
}

pub fn get_integer(doc: &yaml_rust::Yaml, key: &str, default: i64, min: i64, max: i64) -> i64 {
    match doc[key] {
        yaml_rust::Yaml::Integer(i) => {
            if i < min || i > max {
                println!(
                    "Option {} is less/greater than min/max value {}/{}, set {} to {}",
                    key, min, max, key, default
                );
                default
            } else {
                i
            }
        }
        yaml_rust::Yaml::BadValue => {
            println!(
                "Option {} not found or bad integer value, set {} to {}",
                key, key, default
            );
            default
        }
        _ => {
            println!(
                "Wrong value type for {}, expecting string, set {} to {}",
                key, key, default
            );
            default
        }
    }
}

pub fn get_str_arr(doc: &yaml_rust::Yaml, key: &str) -> Vec<String> {
    let mut result = vec![];
    match &doc[key] {
        yaml_rust::Yaml::Array(a) => {
            for element in a {
                match element {
                    yaml_rust::Yaml::String(s) => result.push(String::from(s)),
                    yaml_rust::Yaml::BadValue => println!("Bad string value for {}'s element", key),
                    _ => println!("Wrong value type for {}' element, expecting string", key),
                }
            }
        }
        yaml_rust::Yaml::BadValue => println!(
            "Option {} not found or bad array value, set {} to empty array",
            key, key
        ),
        _ => println!(
            "Wrong value type for {}, expecting array, set {} to empty array",
            key, key
        ),
    }
    result
}
