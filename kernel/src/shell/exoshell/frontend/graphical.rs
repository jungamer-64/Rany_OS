// ============================================================================
// kernel/src/shell/exoshell/frontend/graphical.rs
// ============================================================================

use alloc::format;

use crate::shell::exoshell::display;
use alloc::string::String;

use crate::shell::exoshell::error::ExoResult;
use crate::shell::exoshell::{ExoShell, ExoValue};
use crate::shell::graphical::shell::GraphicalShell;

use super::ShellFrontend;

use crate::io::hid::{KeyCode, KeyEvent, KeyState, Modifiers};
use kernel_api::gui::{InputEvent, KeyState as KapiKeyState};
use kernel_api::services::kernel;

/// Graphical Shell Frontend
/// Wraps the GraphicalShell to provide the ShellFrontend interface.
/// Note: This frontend is unique because it drives the GraphicalShell which
/// owns the framebuffer and manages its own redraw loop.
pub struct GraphicalFrontend {
    // We don't own the shell, we access it via global mutex in async_runtime
    // But for the sake of strict trait impementation, we might need a reference or 
    // we operate on the global singleton.
    // However, clean design implies we should pass the shell instance.
    // Given the global mutex design in `async_runtime.rs`, we will access
    // `GRAPHICAL_SHELL` directly or assume it's passed?
    
    // For now, let's allow it to hold a reference or just be a stateless driver 
    // that uses the global context in `async_runtime`.
    // Actually, `async_runtime` holds the lock.
    // We can make `GraphicalFrontend` hold a `&mut GraphicalShell`.
    // But `ShellFrontend::read_line` is async and needs to yield.
    // We cannot hold a MutexGuard across await.
    
    // Strategy: `read_line` will loop and lock/unlock the global shell instance
    // to update state/check input.
    _marker: (),
}

impl GraphicalFrontend {
    pub fn new() -> Self {
        Self { _marker: () }
    }
}

// Helper to access global shell without holding lock long-term
fn with_global_shell<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut GraphicalShell) -> R,
{
    crate::shell::graphical::async_runtime::with_shell(f)
}

impl ShellFrontend for GraphicalFrontend {
    fn print_message(&mut self, msg: &str) {
        with_global_shell(|shell: &mut GraphicalShell| {
            shell.print(msg);
            if !msg.ends_with('\n') {
                shell.print("\n");
            }
            shell.redraw();
        });
    }

    fn print_prompt(&mut self, _cwd: &str) {
        with_global_shell(|shell: &mut GraphicalShell| {
             // prompt is managed by shell.draw_prompt() which pulls from shell.shell.prompt()
             // So we should make sure shell.shell.cwd is updated first if needed, 
             // but `ExoShell` passed to `read_line` is separate from `GraphicalShell`'s internal `shell`.
             // This is a dual-shell issue.
             // `GraphicalShell` has `pub(crate) shell: ExoShell`.
             // `run_async_shell` maintains `ASYNC_EXOSHELL`.
             
             shell.draw_prompt();
             shell.redraw();
        });
    }

    fn print_result(&mut self, result: &ExoResult<ExoValue<'static>>) {
        with_global_shell(|shell| {
            match result {
                Ok(val) => {
                    if let ExoValue::Exit = val {
                        return;
                    }
                    if let ExoValue::Error(e) = val {
                         let error_color = shell.resources.theme.error;
                         shell.print_colored(&format!("Error: {}\n", e), error_color);
                    } else if let Some(text) = display::format_shell_output(val) {
                        let fg_color = shell.resources.theme.foreground;
                        shell.print_colored(&format!("{}\n", text), fg_color);
                        
                        // Update CWD if changed (Syncs Frontend with Backend)
                        // Note: We need to inspect `val` properly or rely on side channels.
                        // Ideally checking `shell.shell.cwd`? 
                        // But `val` is the result.
                        // `CommandResult` had `cwd`. Here we have raw `ExoValue`.
                        // We can't easily extract new CWD from `ExoValue` unless it IS the cwd.
                        // But `ExoShell` state change happens in `eval`.
                        // The `shell` passed to `read_line` is modified.
                        // We should update `GraphicalShell`'s internal state using the passed `shell`
                        // but `print_result` doesn't take `shell`.
                        
                        // NOTE: Caller should handle sync or we need a way to pass context.
                        // For now, simple print.
                    }
                }
                Err(e) => {
                    let error_color = shell.resources.theme.error;
                     shell.print_colored(&format!("Error: {}\n", e), error_color);
                }
            }
            shell.redraw();
        });
    }

    async fn read_line(&mut self, exoshell: &mut ExoShell) -> Option<String> {
        // Sync graphical shell's internal ExoShell state with the runner's ExoShell
        with_global_shell(|gs| {
            gs.shell.cwd = exoshell.cwd.clone();
            gs.shell.set_history(exoshell.history().to_vec());
            gs.draw_prompt(); 
            gs.redraw();
        });
        
        let mut input_poll_counter = 0u32;

        loop {
            // Get current tick via GuiServices
            let current_time = kernel().gui().map(|g| g.current_tick()).unwrap_or(0);

            // Phase 1: Input Polling
            if let Some(gui_services) = kernel().gui() {
                // Poll input
                for _ in 0..8 {
                    if let Some(input_event) = gui_services.poll_input_event() {
                        with_global_shell(|shell: &mut GraphicalShell| {
                            match input_event {
                                InputEvent::Key(kapi_key) => {
                                    // Convert to KeyEvent
                                     let state = match kapi_key.state {
                                        KapiKeyState::Pressed => KeyState::Pressed,
                                        KapiKeyState::Released => KeyState::Released,
                                    };
                                    let modifiers = Modifiers {
                                        shift: (kapi_key.modifiers & 0x01) != 0,
                                        ctrl: (kapi_key.modifiers & 0x02) != 0,
                                        alt: (kapi_key.modifiers & 0x04) != 0,
                                        alt_gr: (kapi_key.modifiers & 0x08) != 0,
                                        caps_lock: (kapi_key.modifiers & 0x10) != 0,
                                        num_lock: false,
                                        scroll_lock: false,
                                    };
                                    let hid_event = KeyEvent {
                                        key: KeyCode::Unknown,
                                        state,
                                        modifiers,
                                        raw_scancode: kapi_key.scancode,
                                    };
                                    shell.handle_key(hid_event);
                                }
                                InputEvent::Mouse(kapi_mouse) => {
                                    #[cfg(feature = "mouse")]
                                    {
                                        use crate::io::hid::MouseEvent;
                                         let hid_mouse = MouseEvent {
                                            dx: kapi_mouse.dx as i32,
                                            dy: kapi_mouse.dy as i32,
                                            left_down: kapi_mouse.buttons.left(),
                                            right_down: kapi_mouse.buttons.right(),
                                            middle_down: kapi_mouse.buttons.middle(),
                                        };
                                        shell.handle_mouse(hid_mouse);
                                    }
                                }
                            }
                        });
                    } else {
                        break;
                    }
                }
            }

            // 2. Poll Command Queue (Line Submitted?)
            if let Some(req) = crate::shell::graphical::streams::try_recv_command() {
                 exoshell.add_history(req.command.clone());
                 return Some(req.command);
            }

            // 3. Yield & Blink
            if let Some(gui_services) = kernel().gui() {
                gui_services.yield_control();
            } else {
                crate::task::yield_now().await;
            }
            
            // Update Cursor Blink
            input_poll_counter = input_poll_counter.wrapping_add(1);
            if input_poll_counter % 10 == 0 {
                with_global_shell(|shell: &mut GraphicalShell| shell.update_cursor(current_time));
            }
        }
    }
}
