use server::launch;

#[rocket::main]
async fn main() -> Result<(), rocket::Error> {
    launch().await
}
