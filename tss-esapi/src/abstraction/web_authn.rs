use crate::{
    handles::KeyHandle,
    interface_types::session_handles::AuthSession,
    structures::{
        Attest, Data, EccScheme, PcrSelectionList, Public, RsaScheme, Signature, SignatureScheme,
    },
    traits::Marshall,
    Context, Error, Result,
    WrapperErrorKind::InternalError,
};
use ciborium::{cbor, value::Value};
use picky_asn1_x509::SubjectPublicKeyInfo;
use serde_bytes::Bytes;
use sha2::{Digest, Sha256};
use std::convert::{TryFrom, TryInto};

/// WebAuthn TPM Attestation Statement
///
/// Represents a key attestation token as described in [section 8.3](https://www.w3.org/TR/webauthn-2/#sctn-tpm-attestation)
/// of the WebAuthn spec. The token can be (de)serialized to the format described in the spec.
#[derive(Debug)]
pub struct TpmStatement {
    attestation: Attest,
    signature: Signature,
    public_area: Public,
    algorithm: SignatureScheme,
    ak_kid: Vec<u8>,
}

impl TpmStatement {
    /// Generate a new attestation token for the attested key
    pub fn new(
        context: &mut Context,
        attested_key: KeyHandle,
        attesting_key: KeyHandle,
        nonce: Data,
    ) -> Result<TpmStatement> {
        // Get the signing scheme of the attesting key
        let (attesting_key_public_area, _, _) = context.read_public(attesting_key)?;
        let signing_scheme = get_sig_scheme(&attesting_key_public_area)?;
        let ak_kid = get_kid(attesting_key_public_area)?;

        // Generate the TPM-native attestation token
        let (attestation, signature) = context.execute_with_sessions(
            (
                Some(AuthSession::Password),
                Some(AuthSession::Password),
                None,
            ),
            |ctx| ctx.certify(attested_key.into(), attesting_key, nonce, signing_scheme),
        )?;
        // Get public metadata of attested key (`pubArea` in WebAuthn spec)
        let (attested_key_public_area, _, _) = context.read_public(attested_key)?;

        Ok(TpmStatement {
            attestation,
            signature,
            algorithm: signing_scheme,
            public_area: attested_key_public_area,
            ak_kid,
        })
    }

    /// Encodes the token in the format defined by the spec
    pub fn encode(&self) -> Result<Value> {
        let sig = self.signature.clone().marshall()?;
        let pub_area = self.public_area.clone().marshall()?;
        let cert_info = self.attestation.clone().marshall()?;
        let alg = get_alg_value(self.algorithm);
        cbor!({
            "tpmVer" => "2.0",
            "alg" => alg,
            "sig" => &Bytes::new(&sig[..]),
            "kid" => &Bytes::new(&self.ak_kid[..]),
            "pubArea" => &Bytes::new(&pub_area[..]),
            "certInfo" => &Bytes::new(&cert_info[..]),
        })
        .or(Err(Error::local_error(InternalError)))
    }
}

#[derive(Debug)]
pub struct TpmPlatStmt {
    attestation: Attest,
    signature: Signature,
    algorithm: SignatureScheme,
    ak_kid: Vec<u8>,
}

impl TpmPlatStmt {
    pub fn new(
        context: &mut Context,
        key: KeyHandle,
        nonce: Vec<u8>,
        selection_list: PcrSelectionList,
    ) -> Result<TpmPlatStmt> {
        let (key_public_area, _, _) = context.read_public(key)?;
        let signing_scheme = get_sig_scheme(&key_public_area)?;
        let ak_kid = get_kid(key_public_area)?;

        let (attestation, signature) = context
            .execute_with_session(Some(AuthSession::Password), |ctx| {
                ctx.quote(key, nonce.try_into()?, signing_scheme, selection_list)
            })?;
        Ok(TpmPlatStmt {
            attestation,
            signature,
            algorithm: signing_scheme,
            ak_kid,
        })
    }

    pub fn encode(&self) -> Result<Value> {
        let sig = self.signature.clone().marshall()?;
        let cert_info = self.attestation.clone().marshall()?;
        let alg = get_alg_value(self.algorithm);
        cbor!({
            "tpmVer" => "2.0",
            "alg" => alg,
            "sig" => &Bytes::new(&sig[..]),
            "kid" => &Bytes::new(&self.ak_kid[..]),
            "certInfo" => &Bytes::new(&cert_info[..]),
        })
        .or(Err(Error::local_error(InternalError)))
    }
}

fn get_sig_scheme(public_area: &Public) -> Result<SignatureScheme> {
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

fn get_kid(public_area: Public) -> Result<Vec<u8>> {
    let subject_public_key_info = SubjectPublicKeyInfo::try_from(public_area)?;
    let encoded_key = picky_asn1_der::to_vec(&subject_public_key_info)
        .map_err(|_| Error::WrapperError(crate::WrapperErrorKind::InvalidParam))?;
    // Create key ID
    let mut hasher = Sha256::new();
    hasher.update(&encoded_key);
    // Mark ID as "random" (starting with 0x01 tag)
    let mut key_id = vec![0x01_u8];
    key_id.append(&mut hasher.finalize().to_vec());
    Ok(key_id)
}

fn get_alg_value(algorithm: SignatureScheme) -> i32 {
    match algorithm {
        SignatureScheme::RsaSsa { .. } => -65535,
        _ => -1,
    }
}
