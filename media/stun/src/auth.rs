use stun_types::attributes::{
    long_term_password_md5, long_term_password_sha256, MessageIntegrity, MessageIntegrityKey,
    MessageIntegritySha256, MessageIntegritySha256Key, Nonce, PasswordAlgorithm, Realm, Username,
    ALGORITHM_MD5, ALGORITHM_SHA256,
};
use stun_types::{Message, MessageBuilder};

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
        response: &mut Message,
        mut msg: MessageBuilder,
    ) -> Result<(), Error> {
        match &*self {
            StunCredential::ShortTerm { username, password } => {
                msg.add_attr(Username::new(username));

                msg.add_attr_with(
                    MessageIntegritySha256,
                    MessageIntegritySha256Key::new(password),
                );
                msg.add_attr_with(MessageIntegrity, MessageIntegrityKey::new(password));
            }
            StunCredential::LongTerm {
                realm,
                username,
                password,
            } => {
                let key = if let Some(alg) = response.attribute::<PasswordAlgorithm>() {
                    let alg = alg?;

                    match alg.algorithm {
                        ALGORITHM_MD5 => long_term_password_md5(username, realm, password),
                        ALGORITHM_SHA256 => long_term_password_sha256(username, realm, password),
                        _ => return Err(Error::UnknownAlgorithm),
                    }
                } else {
                    long_term_password_md5(username, realm, password)
                };

                let nonce = response.attribute::<Nonce>().ok_or(Error::MissingNonce)??;

                msg.add_attr(Nonce::new(nonce.0));
                msg.add_attr(Realm::new(realm));
                msg.add_attr(Username::new(username));

                msg.add_attr_with(MessageIntegritySha256, MessageIntegritySha256Key::new(&key));
                msg.add_attr_with(MessageIntegrity, MessageIntegrityKey::new(&key));
            }
        }

        Ok(())
    }
}
