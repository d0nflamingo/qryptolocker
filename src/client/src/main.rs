use anyhow::Result;
use client::Client;
use inquire::Select;
use log::{LevelFilter, error, info};

fn main() -> Result<()> {
    pretty_env_logger::formatted_builder()
        .filter_level(LevelFilter::Info)
        .init();

    info!("Starting Client CLI");

    let mut client = Client::default();

    loop {
        let select = Select::new(
            "Testing interface",
            vec![
                "Encrypt",
                "Pay",
                "Unlock one file",
                "Change password",
                "exit",
            ],
        )
        .prompt()?;

        let result = match select {
            "Encrypt" => client.encrypt(),
            "Pay" => client.pay(),
            "Unlock one file" => client.unlock_one(),
            "Change password" => client.change_pwd(),
            "exit" => return Ok(()),
            _ => unreachable!(),
        };

        if let Err(e) = result {
            error!("{e}");
        }
    }
}
