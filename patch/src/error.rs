use thiserror::Error;

#[derive(Error, Debug)]
pub(crate) enum KorePatchError {
    #[error("Input {0} is not a valid JSON")]
    InvalidJSON(String),
}
