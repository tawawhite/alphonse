use std::collections::HashSet;
use std::time::SystemTime;

use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use tls_parser::TlsCertificateContents;
use x509_parser::prelude::{oid2sn, parse_x509_certificate, GeneralName, ParsedExtension};

use crate::TlsProcessor;

#[derive(Clone, Debug, Default, Serialize)]
pub struct CertInfo {
    common_name: HashSet<String>,
    org_name: HashSet<String>,
}

fn serialize_issuer<S>(issuer: &CertInfo, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut state = s.serialize_struct("", 2)?;
    if !issuer.org_name.is_empty() {
        state.serialize_field("issuerON", &issuer.org_name)?;
    }
    if !issuer.common_name.is_empty() {
        state.serialize_field("issuerCN", &issuer.common_name)?;
    }
    state.end()
}

fn serialize_subject<S>(subject: &CertInfo, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut state = s.serialize_struct("", 2)?;
    if !subject.org_name.is_empty() {
        state.serialize_field("subjectON", &subject.org_name)?;
    }
    if !subject.common_name.is_empty() {
        state.serialize_field("subjectCN", &subject.common_name)?;
    }
    state.end()
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Cert {
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    pub alt: HashSet<String>,

    #[serde(skip_serializing_if = "String::is_empty")]
    pub curve: String,

    #[serde(skip_serializing_if = "String::is_empty")]
    pub hash: String,

    #[serde(skip_serializing)]
    pub ca: bool,

    #[serde(flatten)]
    #[serde(serialize_with = "serialize_issuer")]
    pub issuer: CertInfo,

    pub not_after: u64,

    pub not_before: u64,

    #[serde(skip_serializing_if = "String::is_empty")]
    pub public_algorithm: String,

    pub remainingdays: usize,

    #[serde(rename = "serial")]
    pub serial_number: String,

    #[serde(flatten)]
    #[serde(serialize_with = "serialize_subject")]
    pub subject: CertInfo,

    pub valid_days: usize,
}

impl Cert {
    fn update_valid_days(&mut self) {
        let not_before = std::time::UNIX_EPOCH + std::time::Duration::from_millis(self.not_before);
        let not_before = chrono::DateTime::<chrono::Utc>::from(not_before);
        let not_after = std::time::UNIX_EPOCH + std::time::Duration::from_millis(self.not_after);
        let not_after = chrono::DateTime::<chrono::Utc>::from(not_after);
        let diff = not_after - not_before;
        self.valid_days = diff.num_days() as usize;
    }
}

impl TlsProcessor {
    pub fn handle_certificate(&mut self, cert: &TlsCertificateContents) {
        for raw_cert in &cert.cert_chain {
            let mut cert = Cert::default();
            match parse_x509_certificate(raw_cert.data) {
                Err(e) => {
                    eprintln!("parse x509 certitifacte: {}", e);
                    continue;
                }
                Ok((_, cer)) => {
                    // get cert serial number
                    cert.serial_number = format!("{:x}", cer.tbs_certificate.serial);

                    // get issuer information
                    for cn in cer.issuer().iter_common_name() {
                        match cn.as_str() {
                            Ok(cn) => {
                                cert.issuer.common_name.insert(cn.to_string());
                            }
                            Err(_) => continue,
                        }
                    }

                    for org in cer.issuer().iter_organization() {
                        match org.as_str() {
                            Ok(org) => {
                                cert.issuer.org_name.insert(org.to_string());
                            }
                            Err(_) => continue,
                        }
                    }

                    // get validity information
                    cert.not_before = cer.validity().not_before.timestamp() as u64 * 1000;
                    cert.not_after = cer.validity().not_after.timestamp() as u64 * 1000;

                    // get subject information
                    for cn in cer.subject().iter_common_name() {
                        match cn.as_str() {
                            Ok(cn) => {
                                cert.subject.common_name.insert(cn.to_string());
                            }
                            Err(_) => continue,
                        }
                    }

                    for org in cer.subject().iter_organization() {
                        match org.as_str() {
                            Ok(org) => {
                                cert.subject.org_name.insert(org.to_string());
                            }
                            Err(_) => continue,
                        }
                    }

                    // match cer.signature_algorithm.algorithm {};
                    let oid_registry = x509_parser::objects::oid_registry();
                    cert.public_algorithm =
                        oid2sn(&cer.signature_algorithm.algorithm, oid_registry)
                            .unwrap_or("corrupt")
                            .to_string();

                    if cer.tbs_certificate.subject_pki.algorithm.algorithm
                        == x509_parser::oid_registry::OID_KEY_TYPE_EC_PUBLIC_KEY
                    {
                        match &cer.tbs_certificate.subject_pki.algorithm.parameters {
                            None => cert.curve = "unknown".to_string(),
                            Some(p) => {
                                match p.as_oid() {
                                    Err(_) => cert.curve = "corrupt".to_string(),
                                    Ok(oid) => {
                                        // TODO: x509-parser::objects::OID_REGISTRY is not public, so probably
                                        // all the curves would be recoginzed as unknown
                                        cert.curve = oid2sn(oid, oid_registry)
                                            .unwrap_or("unknown")
                                            .to_string();
                                    }
                                };
                            }
                        }
                    }

                    // get extension infomation
                    for ext in cer.extensions() {
                        match ext.parsed_extension() {
                            ParsedExtension::BasicConstraints(bc) => {
                                cert.ca = bc.ca;
                            }
                            ParsedExtension::KeyUsage(usage) => {
                                cert.ca = usage.key_cert_sign();
                            }
                            ParsedExtension::SubjectAlternativeName(an) => {
                                for gn in &an.general_names {
                                    match gn {
                                        GeneralName::DNSName(n) => {
                                            cert.alt.insert(n.to_string());
                                        }
                                        _ => continue,
                                    }
                                }
                            }
                            _ => continue,
                        };
                    }
                }
            }

            cert.update_valid_days();
            cert.remainingdays = (cert.not_after.saturating_sub(
                SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            )) as usize;
            self.certs.push(cert);
        }
    }
}
