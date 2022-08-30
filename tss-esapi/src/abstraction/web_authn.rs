use crate::{
    constants::SessionType,
    handles::{KeyHandle, SessionHandle},
    interface_types::algorithm::HashingAlgorithm,
    structures::{
        Attest, EccScheme, PcrSelectionList, Public, RsaScheme, Signature, SignatureScheme,
        SymmetricDefinition,
    },
    traits::Marshall,
    Context, Error, Result,
    WrapperErrorKind::InternalError,
};
use ciborium::{cbor, ser::into_writer};
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
        let session_1 = context.start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )?;
        let session_2 = context.start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )?;
        let (key_public_area, _, _) = context.read_public(key)?;
        let signing_scheme = get_sig_scheme(key_public_area)?;
        let (attestation, signature) = context
            .execute_with_sessions((session_1, session_2, None), |ctx| {
                ctx.certify(object.into(), key, nonce.try_into()?, signing_scheme)
            })
            .or_else(|e| {
                context.flush_context(SessionHandle::from(session_1).into())?;
                context.flush_context(SessionHandle::from(session_2).into())?;
                Err(e)
            })?;
        context.flush_context(SessionHandle::from(session_1).into())?;
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

    pub fn encode(&self) -> Result<Vec<u8>> {
        let sig = self.signature.clone().marshall()?;
        let pub_area = self.public_area.clone().marshall()?;
        let cert_info = self.attestation.clone().marshall()?;
        let alg = TpmStatement::get_alg_value(self.algorithm);
        let mut encoded_token = vec![];
        match cbor!({
            //TODO put brakets around x5c and alg
            "x5c" => self.x509_chain.clone(),
            "alg" => alg,
            "sig" => sig,
            "pubArea" => pub_area,
            "certInfo" => cert_info,
        }) {
            Ok(value) => match into_writer(&value, &mut encoded_token) {
                Ok(_) => Ok(encoded_token),
                Err(_) => Err(Error::local_error(InternalError)),
            },
            Err(_) => Err(Error::local_error(InternalError)),
        }
    }

    fn get_alg_value(algorithm: SignatureScheme) -> i32 {
        match algorithm {
            SignatureScheme::RsaSsa { .. } => -65535,
            _ => -1,
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
    pub fn new(
        context: &mut Context,
        key: KeyHandle,
        nonce: Vec<u8>,
        selection_list: PcrSelectionList,
    ) -> Result<TpmPlatStmt> {
        let session_1 = context.start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )?;
        let (key_public_area, _, _) = context.read_public(key)?;
        let signing_scheme = get_sig_scheme(key_public_area)?;
        let (attestation, signature) = context
            .execute_with_sessions((session_1, None, None), |ctx| {
                ctx.quote(key, nonce.try_into()?, signing_scheme, selection_list)
            })
            .or_else(|e| {
                context.flush_context(SessionHandle::from(session_1).into())?;
                Err(e)
            })?;
        context.flush_context(SessionHandle::from(session_1).into())?;
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

    pub fn encode(&self) -> Result<Vec<u8>> {
        let sig = self.signature.clone().marshall()?;
        let cert_info = self.attestation.clone().marshall()?;
        let alg = TpmPlatStmt::get_alg_value(self.algorithm);
        let mut encoded_token = vec![];
        match cbor!({
            //TODO put brakets around x5c and alg
            "x5c" => self.x509_chain.clone(),
            "alg" => alg,
            "sig" => sig,
            "certInfo" => cert_info,
        }) {
            Ok(value) => match into_writer(&value, &mut encoded_token) {
                Ok(_) => Ok(encoded_token),
                Err(_) => Err(Error::local_error(InternalError)),
            },
            Err(_) => Err(Error::local_error(InternalError)),
        }
    }

    fn get_alg_value(algorithm: SignatureScheme) -> i32 {
        match algorithm {
            SignatureScheme::RsaSsa { .. } => -65535,
            _ => -1,
        }
    }
}

fn get_sig_scheme(public_area: Public) -> Result<SignatureScheme> {
    match public_area {
        Public::Rsa { parameters, .. } => match parameters.rsa_scheme() {
            RsaScheme::RsaSsa(hash_scheme) => Ok(SignatureScheme::RsaSsa { hash_scheme }),
            RsaScheme::RsaPss(hash_scheme) => Ok(SignatureScheme::RsaPss { hash_scheme }),
            _ => Err(Error::local_error(InternalError)),
        },
        Public::Ecc { parameters, .. } => match parameters.ecc_scheme() {
            EccScheme::EcDsa(hash_scheme) => Ok(SignatureScheme::EcDsa { hash_scheme }),
            _ => Err(Error::local_error(InternalError)),
        },
        _ => Err(Error::local_error(InternalError)),
    }
}
