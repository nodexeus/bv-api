use displaydoc::Display;
use thiserror::Error;

use crate::grpc::common;

#[derive(Debug, Display, Error)]
pub enum Error {
    /// Unknown SearchOperator.
    UnknownSearchOperator,
}

#[derive(Clone, Copy, Debug)]
pub enum SearchOperator {
    Or,
    And,
}

impl TryInto<SearchOperator> for common::SearchOperator {
    type Error = Error;

    fn try_into(self) -> Result<SearchOperator, Self::Error> {
        match self {
            Self::Unspecified => Err(Error::UnknownSearchOperator),
            Self::Or => Ok(SearchOperator::Or),
            Self::And => Ok(SearchOperator::And),
        }
    }
}
