use tls_parser::TlsCertificateContents;
use x509_parser::prelude::{parse_x509_certificate, GeneralName, ParsedExtension};

use crate::Processor;

impl<'a> Processor<'static> {
    pub fn handle_certificate(&mut self, cert: &TlsCertificateContents) {
        for raw_cert in &cert.cert_chain {
            let mut cert = crate::Cert::default();
            match parse_x509_certificate(raw_cert.data) {
                Err(_) => continue,
                Ok((_, cer)) => {
                    // get cert serial number
                    cert.serial_number = format!("{:x}", cer.tbs_certificate.serial);

                    // get issuer information
                    for cn in cer.issuer().iter_common_name() {
                        match cn.as_str() {
                            Ok(cn) => cert.issuer.common_name.push(cn.to_string()),
                            Err(_) => continue,
                        }
                    }

                    for org in cer.issuer().iter_organization() {
                        match org.as_str() {
                            Ok(org) => cert.issuer.org_name.push(org.to_string()),
                            Err(_) => continue,
                        }
                    }

                    // get validity information
                    cert.not_before = cer.validity().not_before.timestamp() as u64;
                    cert.not_after = cer.validity().not_after.timestamp() as u64;

                    // get subject information
                    for cn in cer.subject().iter_common_name() {
                        match cn.as_str() {
                            Ok(cn) => cert.issuer.common_name.push(cn.to_string()),
                            Err(_) => continue,
                        }
                    }

                    for org in cer.subject().iter_organization() {
                        match org.as_str() {
                            Ok(org) => cert.issuer.org_name.push(org.to_string()),
                            Err(_) => continue,
                        }
                    }

                    // get extension infomation
                    for ext in cer.extensions().values() {
                        match ext.parsed_extension() {
                            ParsedExtension::KeyUsage(usage) => {}
                            ParsedExtension::SubjectAlternativeName(an) => {
                                for gn in &an.general_names {
                                    match gn {
                                        GeneralName::DNSName(n) => cert.alt.push(n.to_string()),
                                        _ => continue,
                                    }
                                }
                            }
                            _ => continue,
                        };
                    }
                }
            }

            self.certs.push(cert);
        }
    }
}
