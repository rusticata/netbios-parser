use crate::nom;
use nom::{
    error::{ErrorKind, ParseError},
    IResult,
};

pub type Result<'a, T> = IResult<&'a [u8], T, NetbiosError<&'a [u8]>>;

/// An error that can occur while parsing or validating a NetBIOS packet.
#[derive(Debug, PartialEq, thiserror::Error)]
pub enum NetbiosError<I>
where
    I: std::fmt::Debug,
{
    #[error("generic error")]
    Generic,

    #[error("invalid name length")]
    InvalidNameLength,

    #[error("invalid NetBIOS name in Name Service question field")]
    InvalidQuestion,

    #[error("invalid NetBIOS name in Name Service answer field")]
    InvalidAnswer,

    #[error("nom error: {0:?}")]
    NomError(I, ErrorKind),
}

impl<I> From<NetbiosError<I>> for nom::Err<NetbiosError<I>>
where
    I: std::fmt::Debug,
{
    fn from(e: NetbiosError<I>) -> nom::Err<NetbiosError<I>> {
        nom::Err::Error(e)
    }
}

impl<I> ParseError<I> for NetbiosError<I>
where
    I: std::fmt::Debug,
{
    fn from_error_kind(input: I, kind: ErrorKind) -> Self {
        NetbiosError::NomError(input, kind)
    }
    fn append(input: I, kind: ErrorKind, _other: Self) -> Self {
        NetbiosError::NomError(input, kind)
    }
}
