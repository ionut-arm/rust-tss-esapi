use crate::{
    constants::SessionType,
    handles::{KeyHandle, SessionHandle},
    interface_types::algorithm::HashingAlgorithm,
    structures::{
        pcr_selection_list::PcrSelectionListBuilder, Attest, HashScheme, Public, Signature,
        SignatureScheme, SymmetricDefinition,
    },
    traits::Marshall,
    Context, Result,
};
use ciborium::cbor;
use std::convert::TryInto;

#[derive(Debug)]
pub struct TpmStatement {
    attestation: Attest,
    signature: Signature,
    public_area: Public,
    algorithm: SignatureScheme,
    x509_chain: Vec<Vec<u8>>,
}

impl TpmStatement {
    pub fn new(
        context: &mut Context,
        object: KeyHandle,
        key: KeyHandle,
        nonce: Vec<u8>,
    ) -> Result<TpmStatement> {
        let (public_area, _, _) = context.read_public(object)?;
        let (session_1, _, _) = context.sessions();
        let session_2 = context.start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )?;
        let signing_scheme = SignatureScheme::RsaSsa {
            hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
        };
        let (attestation, signature) = context
            .execute_with_sessions((session_1, session_2, None), |ctx| {
                ctx.certify(object.into(), key, nonce.try_into()?, signing_scheme)
            })
            .or_else(|e| {
                context.flush_context(object.into())?;
                context.flush_context(key.into())?;
                context.flush_context(SessionHandle::from(session_2).into())?;
                Err(e)
            })?;
        context.flush_context(object.into())?;
        context.flush_context(key.into())?;
        context.flush_context(SessionHandle::from(session_2).into())?;
        Ok(TpmStatement {
            attestation,
            signature,
            x509_chain: Vec::new(),
            algorithm: signing_scheme,
            public_area,
        })
    }

    pub fn add_certificates(&mut self, mut certificates: Vec<Vec<u8>>) {
        self.x509_chain.append(&mut certificates);
    }

    pub fn convert_to_tpmstmtformat_and_encode(&self) -> Vec<u8> {
        let cert_info_value: Vec<u8>;
        let sig_value: Vec<u8>;
        let pub_area_value: Vec<u8>;
        match self.signature.clone().marshall() {
            Ok(sig) => sig_value = sig,
            Err(_) => panic!("tried to convert Err type"),
        };
        match self.public_area.clone().marshall() {
            Ok(pub_area) => pub_area_value = pub_area,
            Err(_) => panic!("tried to convert Err type"),
        };
        match self.attestation.clone().marshall() {
            Ok(cert_info) => cert_info_value = cert_info,
            Err(_) => panic!("tried to convert Err type"),
        };
        let mut alg_value = -1;
        if let SignatureScheme::RsaSsa { hash_scheme: _ } = self.algorithm {
            alg_value = -65535
        };
        match cbor!({
            //TODO put brakets around x5c and alg
            "x5c" => self.x509_chain.clone(),
            "alg" => alg_value,
            "sig" => sig_value,
            "pubArea" => pub_area_value,
            "certInfo" => cert_info_value,
        })
        .unwrap()
        .as_bytes()
        {
            Some(value) => value.clone(),
            None => panic!("tried to convert None type"),
        }
    }
}

#[derive(Debug)]
pub struct TpmPlatStmt {
    attestation: Attest,
    signature: Signature,
    algorithm: SignatureScheme,
    x509_chain: Vec<Vec<u8>>,
}

impl TpmPlatStmt {
    pub fn new(context: &mut Context, key: KeyHandle, nonce: Vec<u8>) -> Result<TpmPlatStmt> {
        let (session_1, _, _) = context.sessions();
        let session_2 = context.start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )?;
        let signing_scheme = SignatureScheme::RsaSsa {
            hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
        };
        let selection_list = PcrSelectionListBuilder::new();
        let (attestation, signature) = context
            .execute_with_sessions((session_1, session_2, None), |ctx| {
                ctx.quote(
                    key,
                    nonce.try_into()?,
                    signing_scheme,
                    selection_list.build()?,
                )
            })
            .or_else(|e| {
                context.flush_context(key.into())?;
                context.flush_context(SessionHandle::from(session_2).into())?;
                Err(e)
            })?;
        context.flush_context(key.into())?;
        context.flush_context(SessionHandle::from(session_2).into())?;
        Ok(TpmPlatStmt {
            attestation,
            signature,
            x509_chain: Vec::new(),
            algorithm: signing_scheme,
        })
    }

    pub fn add_certificates(&mut self, mut certificates: Vec<Vec<u8>>) {
        self.x509_chain.append(&mut certificates);
    }

    pub fn convert_to_tpmplatstmtformat_and_encode(&self) -> Vec<u8> {
        let cert_info_value: Vec<u8>;
        let sig_value: Vec<u8>;
        match self.signature.clone().marshall() {
            Ok(sig) => sig_value = sig,
            Err(_) => panic!("tried to convert Err type"),
        };
        match self.attestation.clone().marshall() {
            Ok(cert_info) => cert_info_value = cert_info,
            Err(_) => panic!("tried to convert Err type"),
        };
        let mut alg_value = -1;
        if let SignatureScheme::RsaSsa { hash_scheme: _ } = self.algorithm {
            alg_value = -65535
        };
        match cbor!({
            //TODO put brakets around x5c and alg
            "x5c" => self.x509_chain.clone(),
            "alg" => alg_value,
            "sig" => sig_value,
            "certInfo" => cert_info_value,
        })
        .unwrap()
        .as_bytes()
        {
            Some(value) => value.clone(),
            None => panic!("tried to convert None type"),
        }
    }
}
