// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::{KeyMaterial, KeyParams, ObjectWrapper, TransientKeyContext};
use crate::{
    abstraction::{ek, web_authn},
    attributes::ObjectAttributesBuilder,
    constants::SessionType,
    error::{Error, WrapperErrorKind},
    handles::{AuthHandle, KeyHandle, SessionHandle},
    interface_types::{
        algorithm::{AsymmetricAlgorithm, HashingAlgorithm},
        session_handles::{AuthSession, PolicySession},
    },
    structures::{
        Auth, EncryptedSecret, IdObject, PcrSelectionList, RsaScheme, SymmetricDefinition,
    },
    traits::Marshall,
    utils::PublicKey,
    Result,
};
use std::convert::{TryFrom, TryInto};

#[derive(Debug)]
/// Wrapper for the parameters needed by MakeCredential
///
/// The 3rd party requesting proof that the key is indeed backed
/// by a TPM would perform a MakeCredential and would thus require
/// `name` and `attesting_key_pub` as inputs for that operation.
///
/// `public` is not strictly needed, however it is returned as a
/// convenience block of data. Since the MakeCredential operation
/// bakes into the encrypted credential the identity of the key to
/// be attested via its `name`, the correctness of the `name` must
/// be verifiable by the said 3rd party. `public` bridges this gap:
///
/// * it includes all the public parameters of the attested key
/// * can be hashed (in its marshaled form) with the name hash
/// (found by unmarshaling it) to obtain `name`
pub struct MakeCredParams {
    /// TPM name of the object being attested
    pub name: Vec<u8>,
    /// Encoding of the public parameters of the object whose name
    /// will be included in the credential computations
    pub public: Vec<u8>,
    /// Public part of the key used to protect the credential
    pub attesting_key_pub: PublicKey,
}

struct AttestingKeyCustomization;
impl super::KeyCustomization for AttestingKeyCustomization {
    /// Alter the attributes used on key creation
    fn attributes(&self, attributes_builder: ObjectAttributesBuilder) -> ObjectAttributesBuilder {
        attributes_builder.with_restricted(true)
    }
}

impl TransientKeyContext {
    /// Create a new attesting key (AIK).
    ///
    /// The AIK is created as a descendant of the context root key, with the given parameters.
    ///
    /// If successful, the result contains the [KeyMaterial] of the key and a vector of
    /// bytes forming the authentication value for said key.
    ///
    /// The following key attributes are always **set**: `fixed_tpm`, `fixed_parent`, `sensitive_data_origin`,
    /// `user_with_auth`, `restricted`. See section 8.3 in the Structures spec for a detailed description
    /// of these attributes.
    ///
    /// # Constraints
    /// * `auth_size` must be at most 32
    ///
    /// # Errors
    /// * if the authentication size is larger than 32 a `WrongParamSize` wrapper error is returned
    /// * if the key params specify an encryption scheme, `InvalidParam` wrapper error is returned
    pub fn create_aik(
        &mut self,
        key_params: KeyParams,
        auth_size: usize,
    ) -> Result<(KeyMaterial, Option<Auth>)> {
        if matches!(
            key_params,
            KeyParams::Rsa {
                scheme: RsaScheme::RsaEs,
                ..
            } | KeyParams::Rsa {
                scheme: RsaScheme::Oaep(..),
                ..
            }
        ) {
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }
        self.create_key_internal(key_params, auth_size, AttestingKeyCustomization {})
    }

    /// Get the data required to perform a MakeCredential
    ///
    /// # Parameters
    ///
    /// * `object` - the object whose TPM name will be included in
    /// the credential
    /// * `key` - the key to be used to encrypt the secret that wraps
    /// the credential
    ///
    /// **Note**: If no `key` is given, the default Endorsement Key
    /// will be used.
    pub fn get_make_cred_params(
        &mut self,
        object: ObjectWrapper,
        key: Option<ObjectWrapper>,
    ) -> Result<MakeCredParams> {
        let object_handle = self.load_key(object.params, object.material, None)?;
        let (object_public, object_name, _) =
            self.context.read_public(object_handle).or_else(|e| {
                self.context.flush_context(object_handle.into())?;
                Err(e)
            })?;
        self.context.flush_context(object_handle.into())?;

        // Name of objects is derived from their publicArea, i.e. the marshaled TPMT_PUBLIC
        let public = object_public.marshall()?;

        let attesting_key_pub = match key {
            None => get_ek_object_public(&mut self.context)?,
            Some(key) => key.material.public,
        };
        Ok(MakeCredParams {
            name: object_name.value().to_vec(),
            public,
            attesting_key_pub,
        })
    }

    /// Perform an ActivateCredential operation for the given object
    ///
    /// # Parameters
    ///
    /// * `object` - the object whose TPM name is included in the credential
    /// * `key` - the key used to encrypt the secret that wraps the credential
    /// * `credential_blob` - encrypted credential that will be returned by the
    /// TPM
    /// * `secret` - encrypted secret that was used to encrypt the credential
    ///
    /// **Note**: if no `key` is given, the default Endorsement Key
    /// will be used. You can find more information about the default Endorsement
    /// Key in the [ek] module.
    pub fn activate_credential(
        &mut self,
        object: ObjectWrapper,
        key: Option<ObjectWrapper>,
        credential_blob: Vec<u8>,
        secret: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let credential_blob = IdObject::try_from(credential_blob)?;
        let secret = EncryptedSecret::try_from(secret)?;
        let object_handle = self.load_key(object.params, object.material, object.auth)?;
        let (key_handle, session_2) = match key {
            Some(key) => self.prepare_attesting_key(key),
            None => self.prepare_ek_activate_cred(),
        }
        .or_else(|e| {
            self.context.flush_context(object_handle.into())?;
            Err(e)
        })?;

        let (session_1, _, _) = self.context.sessions();
        let credential = self
            .context
            .execute_with_sessions((session_1, session_2, None), |ctx| {
                ctx.activate_credential(object_handle, key_handle, credential_blob, secret)
            })
            .or_else(|e| {
                self.context.flush_context(object_handle.into())?;
                self.context.flush_context(key_handle.into())?;
                self.context
                    .flush_context(SessionHandle::from(session_2).into())?;
                Err(e)
            })?;

        self.context.flush_context(object_handle.into())?;
        self.context.flush_context(key_handle.into())?;
        self.context
            .flush_context(SessionHandle::from(session_2).into())?;
        Ok(credential.as_bytes().to_vec())
    }

    // No key was given, use the EK. This requires using a Policy session
    fn prepare_ek_activate_cred(&mut self) -> Result<(KeyHandle, Option<AuthSession>)> {
        let session = self.context.start_auth_session(
            None,
            None,
            None,
            SessionType::Policy,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )?;
        let _ = self.context.policy_secret(
            PolicySession::try_from(session.unwrap())
                .expect("Failed to convert auth session to policy session"),
            AuthHandle::Endorsement,
            Default::default(),
            Default::default(),
            Default::default(),
            None,
        );
        Ok((
            ek::create_ek_object(&mut self.context, AsymmetricAlgorithm::Rsa, None).or_else(
                |e| {
                    self.context
                        .flush_context(SessionHandle::from(session).into())?;
                    Err(e)
                },
            )?,
            session,
        ))
    }

    // Load key and create a HMAC session for it
    fn prepare_attesting_key(
        &mut self,
        key: ObjectWrapper,
    ) -> Result<(KeyHandle, Option<AuthSession>)> {
        let session = self.context.start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )?;
        Ok((
            self.load_key(key.params, key.material, key.auth)
                .or_else(|e| {
                    self.context
                        .flush_context(SessionHandle::from(session).into())?;
                    Err(e)
                })?,
            session,
        ))
    }

    pub fn quote(
        &mut self,
        key: ObjectWrapper,
        nonce: Vec<u8>,
        selection_list: PcrSelectionList,
    ) -> Result<web_authn::TpmPlatStmt> {
        let key_handle = self.load_key(key.params, key.material, key.auth)?;

        let statement =
            web_authn::TpmPlatStmt::new(&mut self.context, key_handle, nonce, selection_list);
        self.context.flush_context(key_handle.into())?;
        statement
    }

    pub fn certify(
        &mut self,
        object: ObjectWrapper,
        key: ObjectWrapper,
        nonce: Vec<u8>,
    ) -> Result<web_authn::TpmStatement> {
        let object_handle = self.load_key(object.params, object.material, object.auth)?;
        let key_handle = self.load_key(key.params, key.material, key.auth)?;

        let statement = web_authn::TpmStatement::new(
            &mut self.context,
            object_handle,
            key_handle,
            nonce.try_into()?,
        );
        self.context.flush_context(key_handle.into())?;
        self.context.flush_context(object_handle.into())?;
        statement
    }
}

fn get_ek_object_public(context: &mut crate::Context) -> Result<PublicKey> {
    let key_handle = ek::create_ek_object(context, AsymmetricAlgorithm::Rsa, None)?;
    let (attesting_key_pub, _, _) = context.read_public(key_handle).or_else(|e| {
        context.flush_context(key_handle.into())?;
        Err(e)
    })?;
    context.flush_context(key_handle.into())?;

    PublicKey::try_from(attesting_key_pub)
}
