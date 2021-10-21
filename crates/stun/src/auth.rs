use stun_types::attributes::{
    MessageIntegrity, MessageIntegrityKey, MessageIntegritySha256, Nonce, PasswordAlgorithm, Realm,
    Username, ALGORITHM_MD5, ALGORITHM_SHA256,
};
use stun_types::builder::MessageBuilder;
use stun_types::parse::ParsedMessage;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Parse(#[from] stun_types::Error),
    #[error("missing nonce in response")]
    MissingNonce,
    #[error("password algorithm contained an unknown value")]
    UnknownAlgorithm,
}

pub enum StunCredential {
    ShortTerm {
        username: String,
        password: String,
    },
    LongTerm {
        realm: String,
        username: String,
        password: String,
    },
}

impl StunCredential {
    pub fn authenticate(
        &mut self,
        response: &mut ParsedMessage,
        mut msg: MessageBuilder,
    ) -> Result<(), Error> {
        match &*self {
            StunCredential::ShortTerm { username, password } => {
                msg.add_attr(&Username::new(username))?;

                let key = MessageIntegrityKey::new_short_term(password);

                msg.add_attr_with(&MessageIntegritySha256::default(), &key)?;
                msg.add_attr_with(&MessageIntegrity::default(), &key)?;
            }
            StunCredential::LongTerm {
                realm,
                username,
                password,
            } => {
                let key = if let Some(alg) = response.get_attr::<PasswordAlgorithm>() {
                    let alg = alg?;

                    match alg.algorithm {
                        ALGORITHM_MD5 => {
                            MessageIntegrityKey::new_long_term_md5(username, realm, password)
                        }
                        ALGORITHM_SHA256 => {
                            MessageIntegrityKey::new_long_term_sha256(username, realm, password)
                        }
                        _ => return Err(Error::UnknownAlgorithm),
                    }
                } else {
                    MessageIntegrityKey::new_long_term_md5(username, realm, password)
                };

                let nonce = response.get_attr::<Nonce>().ok_or(Error::MissingNonce)??;

                msg.add_attr(&Nonce::new(nonce.0))?;
                msg.add_attr(&Realm::new(realm))?;
                msg.add_attr(&Username::new(username))?;

                msg.add_attr_with(&MessageIntegritySha256::default(), &key)?;
                msg.add_attr_with(&MessageIntegrity::default(), &key)?;
            }
        }

        Ok(())
    }
}
