use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

// Errors
pub enum Errors {
    ErrorState,
    ErrorInvalidIP,
    ErrorMaxAttemptsOfRequests,
    ErrorInvalidBody,
}

impl IntoResponse for Errors {
    fn into_response(self) -> Response {
        match self {
            Errors::ErrorState => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json("Error: with the internal state of the server"),
            )
                .into_response(),
            Errors::ErrorInvalidIP => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json("Error: the IP is invalid")
            )
                .into_response(),
            Errors::ErrorMaxAttemptsOfRequests => (
                StatusCode::INTERNAL_SERVER_ERROR, 
                Json("Error: the maximum number of requests attempts for this ip has been reached, please wait before trying again")
            )
                .into_response(),
            Errors::ErrorInvalidBody => (
                StatusCode::INTERNAL_SERVER_ERROR, 
                Json("Error: the body is invalid or empty")
            )
                .into_response(),
        }
    }
}
