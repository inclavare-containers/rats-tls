use serde::{Deserialize, Serialize};
use sev::certs::sev::Certificate;
use sev::firmware::AttestationReport;

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
#[repr(C, packed)]
pub struct SevEvidence {
    pub report: AttestationReport, // The attestation report
    pub cek: Certificate,          // The certificate for the CEK.
    pub pek: Certificate,          // The certificate for the PEK.
    pub oca: Certificate,          // The certificate for the OCA.
    pub device_type: DeviceType,   // The SEV PSP device type
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone, Copy)]
pub enum DeviceType {
    AmdRome,
    AmdNaples,
    AmdMilan,
    Unknown,
}
