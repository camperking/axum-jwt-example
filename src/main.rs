use std::{collections::HashMap, sync::Arc};

use axum::{
    extract::State,
    headers::authorization::{Authorization, Bearer},
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
    Json, Router, TypedHeader,
};
use jwt_simple::prelude::*;

#[derive(Debug, Deserialize)]
struct User {
    name: String,
    _password: String,
}

struct AppState {
    jwt_key: HS256Key,
}

#[tokio::main]
async fn main() {
    let mut users: HashMap<&str, &str> = HashMap::new();
    users.insert("user1", "password");

    let users = Arc::from(users);

    let app_state = Arc::new(AppState {
        jwt_key: HS256Key::generate(),
    });

    // auth and receive jwt
    let app = Router::new()
        .route(
            "/auth",
            post(
                |state: State<Arc<AppState>>, Json(payload): Json<User>| async move {
                    println!("Payload: {:#?}", payload);
                    println!("Users: {:#?}", users);
                    let user = users.iter().find(|&user| *user.0 == payload.name);

                    let user = match user {
                        Some(user) => user,
                        None => return Err(StatusCode::NOT_FOUND),
                    };

                    let claims = Claims::create(Duration::from_hours(2));
                    let token = state.jwt_key.authenticate(claims).unwrap();

                    println!("user found: {:#?}", user);
                    Ok(token)
                },
            ),
        )
        .route(
            "/verify",
            post(|state: State<Arc<AppState>>, body: String| async move {
                println!("Body: {:#?}", body);

                let claims = state.jwt_key.verify_token::<NoCustomClaims>(&body, None);
                let claims = match claims {
                    Ok(c) => c,
                    Err(err) => {
                        println!("jwt error: {:#?}", err);
                        return Err(StatusCode::UNAUTHORIZED);
                    }
                };

                println!("Claims: {:#?}", claims);

                Ok("ok")
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
    let claims = state
        .jwt_key
        .verify_token::<NoCustomClaims>(auth.token(), None);
    let claims = match claims {
        Ok(c) => c,
        Err(_) => return Err(StatusCode::UNAUTHORIZED),
    };

    println!("Claims: {:#?}", claims);

    let response = next.run(req).await;

    Ok(response)
}
