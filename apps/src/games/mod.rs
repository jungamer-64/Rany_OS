// apps/src/games/mod.rs - Games Application
//!
//! Simple games collection implementing the Application trait.

#![allow(dead_code)]
#![allow(unused_imports)]

use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;

use app_sdk::{AppContext, Application, print};

/// Games launcher application
pub struct Games;

impl Games {
    pub fn new() -> Self {
        Self
    }

    async fn run_games(&mut self, _ctx: AppContext) {
        print(format_args!("ExoRust Games v0.1.0\n"));
        print(format_args!("Available games:\n"));
        print(format_args!("  1. Snake\n"));
        print(format_args!("  2. Tetris\n"));
        print(format_args!("  3. Minesweeper\n"));
        print(format_args!("\nSelect a game (1-3): "));

        // Game selection loop would go here
    }
}

impl Default for Games {
    fn default() -> Self {
        Self::new()
    }
}

impl Application for Games {
    fn on_start(&mut self, ctx: AppContext) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        let mut games = Games::new();
        Box::pin(async move {
            games.run_games(ctx).await;
        })
    }

    fn on_stop(&mut self) {
        print(format_args!("Games closing...\n"));
    }

    fn name(&self) -> &str {
        "games"
    }
}
