use eframe::egui;
use rand::TryRngCore;
use rand::rngs::OsRng;
use hex;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{self, Sender};
use crate::egui::{ViewportBuilder, Context};
mod public_adress;

struct MouseEntropyApp {
    entropy_collected: f32,
    last_mouse_pos: (f32, f32),
    total_distance: f32,
    private_key: Arc<Mutex<[u8; 32]>>,
    required_distance: f32,
    key_generated: bool,
    display_key: String,
    should_close: bool,      
    key_sender: Option<Sender<String>>, 
}

impl Default for MouseEntropyApp {
    fn default() -> Self {
        let mut key = [0u8; 32];
        OsRng.try_fill_bytes(&mut key).unwrap();

        let (tx, _rx) = mpsc::channel();

        Self {
            entropy_collected: 0.0,
            last_mouse_pos: (0.0, 0.0),
            total_distance: 0.0,
            private_key: Arc::new(Mutex::new(key)),
            required_distance: 10000.0,
            key_generated: false,
            display_key: String::new(),
            should_close: false,
            key_sender: Some(tx),
        }
    }
}

impl eframe::App for MouseEntropyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Bitcoin Private Key Generator");
            ui.add_space(10.0);
            
            ui.label("Move your mouse over this red area to generate entropy:");
            
            let response = ui.allocate_rect(
                egui::Rect::from_min_size(
                    ui.cursor().min, 
                    egui::vec2(ui.available_width(), 400.0)
                ),
                egui::Sense::hover(),
            );
            
            ui.painter().rect_filled(
                response.rect,
                8.0,
                egui::Color32::from_rgb(200, 10, 10),
            );
            

            if response.hovered() {
                let mouse_pos = ctx.input(|i| i.pointer.hover_pos());
                
                if let Some(pos) = mouse_pos {
                    if self.last_mouse_pos != (0.0, 0.0) {
                        let dx = pos.x - self.last_mouse_pos.0;
                        let dy = pos.y - self.last_mouse_pos.1;
                        let distance = (dx * dx + dy * dy).sqrt();
                        
                        self.total_distance += distance;
                        self.entropy_collected = (self.total_distance / self.required_distance).min(1.0);
                        
                        if let Ok(mut key) = self.private_key.lock() {
                            let pos_x = pos.x.to_bits();
                            let pos_y = pos.y.to_bits();
                            

                            key[0] ^= ((pos_x >> 0) & 0xFF) as u8;
                            key[1] ^= ((pos_x >> 8) & 0xFF) as u8;
                            key[2] ^= ((pos_x >> 16) & 0xFF) as u8;
                            key[3] ^= ((pos_x >> 24) & 0xFF) as u8;
                            key[4] ^= ((pos_y >> 0) & 0xFF) as u8;
                            key[5] ^= ((pos_y >> 8) & 0xFF) as u8;
                            key[6] ^= ((pos_y >> 16) & 0xFF) as u8;
                            key[7] ^= ((pos_y >> 24) & 0xFF) as u8;
                            

                            let timestamp = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap()
                                .as_nanos();
                            
                            key[8] ^= ((timestamp >> 0) & 0xFF) as u8;
                            key[9] ^= ((timestamp >> 8) & 0xFF) as u8;
                            key[10] ^= ((timestamp >> 16) & 0xFF) as u8;
                            key[11] ^= ((timestamp >> 24) & 0xFF) as u8;

 
                        }
                    }
                    
                    self.last_mouse_pos = (pos.x, pos.y);
                }
            }
            
            ui.add_space(10.0);
            ui.label(format!("Entropy collected: {:.1}%", self.entropy_collected * 100.0));
            ui.add(egui::ProgressBar::new(self.entropy_collected).show_percentage());
            ui.add_space(20.0);
            
            if ui.button("Generate Private Key").clicked() || 
               (ui.input(|i| i.key_pressed(egui::Key::Enter)) && self.entropy_collected > 0.9) {
                if let Ok(mut key) = self.private_key.lock() {
                    let mut final_key = [0u8; 32];
                    OsRng.try_fill_bytes(&mut final_key).unwrap();
                    
                    for i in 0..32 {
                        key[i] ^= final_key[i];
                    }
                    
                    self.display_key = hex::encode(&*key); 
                }
                
                self.key_generated = true;
            }
            

            if self.key_generated {
                ui.add_space(10.0);
                ui.heading("Your Bitcoin Private Key:");
                ui.add_space(5.0);
                
                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.add(egui::TextEdit::multiline(&mut self.display_key.as_str())
                        .desired_width(ui.available_width())
                        .desired_rows(2)
                        .code_editor());
                });
                
                if ui.button("Copy to clipboard").clicked() {
                    ui.output_mut(|_o| Context::copy_text(ctx, self.display_key.clone()));
                }
                
                ui.add_space(10.0);
                ui.label("Keep this key secret and secure! Anyone with access to this key has access to your Bitcoin.");

                if ui.button("Done").clicked() {
                    self.should_close = true;

                    if let Some(sender) = self.key_sender.take() {
                        let _ = sender.send(self.display_key.clone()); // Send key to main()
                    }
                }
            }
        });
        if self.should_close {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }
}


fn main() -> Result<(), eframe::Error> {
    let (tx, rx) = std::sync::mpsc::channel();

    let options = eframe::NativeOptions {
        viewport: ViewportBuilder::default()
            .with_inner_size([500.0, 500.0]),
        ..Default::default()
    };

    let _ = eframe::run_native(
        "Bitcoin Private Key Generator",
        options,
        Box::new(|_cc| Ok(Box::new(MouseEntropyApp {
            key_sender: Some(tx),
            ..Default::default()
        }))),
    );

    match rx.recv() {
        Ok(private_key) => {
            println!("Private Key received: {}", private_key);
            let public_key_segwit = crate::public_adress::generate_btc_address(&private_key, "segwit");
            let public_key_legacy = crate::public_adress::generate_btc_address(&private_key, "legacy");
            println!("Public adress segwit: {}", public_key_segwit);
            println!("Public adress legacy: {}", public_key_legacy);
            Ok(())
        }
        Err(_) => {
            println!("Error receiving private key.");
            Ok(())
        }
    }



}
