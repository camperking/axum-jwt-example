use rand::Rng;
use std::{sync::Arc, time::SystemTime};

use axum::{
    extract::State,
    headers::authorization::{Authorization, Bearer},
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
    Router, TypedHeader,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: u64,
}

struct AppState {
    jwt_enc_key: EncodingKey,
    jwt_dec_key: DecodingKey,
}

#[tokio::main]
async fn main() {
    let mut arr = [0u8; 32];
    rand::thread_rng().try_fill(&mut arr[..]).unwrap();

    let app_state = Arc::new(AppState {
        jwt_enc_key: EncodingKey::from_secret(&arr),
        jwt_dec_key: DecodingKey::from_secret(&arr),
    });

    // auth and receive jwt
    let app = Router::new()
        .route(
            "/auth",
            post(|state: State<Arc<AppState>>| async move {
                let claims = Claims {
                    sub: "user".to_string(),
                    exp: SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                        + 3600,
                };

                let token = encode(&Header::default(), &claims, &state.jwt_enc_key).unwrap();

                token
            }),
        )
        .route(
            "/verify",
            post(|state: State<Arc<AppState>>, body: String| async move {
                let token =
                    decode::<Claims>(&body, &state.jwt_dec_key, &Validation::default()).unwrap();

                format!(
                    "token for {:?} expires at {:?}",
                    token.claims.sub, token.claims.exp
                )
            }),
        )
        .route(
            "/secured",
            get(|| async {
                "secured site accessed with jwt sent as \"Autorization: Bearer\" header token"
            })
            .layer(middleware::from_fn_with_state(
                app_state.clone(),
                jwt_middleware,
            )),
        )
        .with_state(app_state);

    // run it with hyper on localhost:3000
    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn jwt_middleware<B>(
    State(state): State<Arc<AppState>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    req: Request<B>,
    next: Next<B>,
) -> Result<Response, StatusCode> {
    let _token =
        decode::<Claims>(&auth.token(), &state.jwt_dec_key, &Validation::default()).unwrap();

    let response = next.run(req).await;

    Ok(response)
}
