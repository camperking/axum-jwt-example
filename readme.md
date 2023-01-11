# Axum JWT example

This is a simple webserver written in Rust. It uses Axum and shows basic handling of JsonWebTokens.

Try it with `cargo run` and then use the test.http with eg. "REST Client" extension for VsCode.

There are three routes:
- a post request to /auth gives back a jwt as a string
- a post to /verify with the token as the body, checks it with the secret on the server
- a get request to /secured is layered by a middleware and will always fail if no valid `Authorization: Bearer token` header is set.