mod agent;
use agent::agent::scan_for_secrets;
use futures_util::StreamExt as _;
use actix_multipart::Multipart;
use actix_web::{ web, App, HttpResponse, HttpServer, Responder};

async fn index() -> impl Responder {
    HttpResponse::Ok().content_type("text/html").body(include_str!("templates/index.html"))
}

async fn detect_secrets(mut payload: Multipart) -> impl Responder {
    let mut data:String = String::new();
    while let Some(item) = payload.next().await {
        let mut field = match item {
            Ok(field) => field,
            Err(e) => return HttpResponse::InternalServerError().body(format!("Error processing field: {}", e)),
        };
        let content_type = field.content_type().unwrap().to_string();
        if content_type != "text/plain" {
            return HttpResponse::BadRequest().body("Only text files are allowed");
        }

        let mut file_data = Vec::new();

        while let Some(chunk) = field.next().await {
            match chunk {
                Ok(data) => file_data.extend_from_slice(&data),
                Err(e) => return HttpResponse::InternalServerError().body(format!("Error processing chunk: {}", e)),
            }
        }

        let file_content = match String::from_utf8(file_data) {
            Ok(content) => content,
            Err(e) => return HttpResponse::InternalServerError().body(format!("Error converting file data to string: {}", e)),
        };

        data = scan_for_secrets(file_content);
    }
    HttpResponse::Ok().body(data)
}

#[actix_web::main]
async fn main() ->std::io::Result<()>{
    let port = 4040;
    HttpServer::new(|| {
        App::new()
            .route("/", web::get().to(index))
            .route("/", web::post().to(detect_secrets))
    })
    .bind(("127.0.0.1", port))?
    .run()
    .await
}
