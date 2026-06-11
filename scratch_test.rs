use hyper::{Request, Response, StatusCode};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use std::convert::Infallible;
use hyper::body::Incoming;

pub async fn handle(req: Request<Incoming>) -> Result<Response<http_body_util::combinators::BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    if req.uri().path() == "/api/events/stream" {
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<hyper::body::Frame<Bytes>, hyper::Error>>(100);
        // mock stream task
        tokio::spawn(async move {
            let _ = tx.send(Ok(hyper::body::Frame::data(Bytes::from("data: hello\n\n")))).await;
        });
        let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
        let body = http_body_util::StreamBody::new(stream).boxed();
        return Ok(Response::new(body));
    }
    
    let res = Response::new(Full::new(Bytes::from("OK")));
    Ok(res.map(|b| b.map_err(|e| match e {}).boxed()))
}
