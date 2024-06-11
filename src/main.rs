use crypto_layer::SecurityModuleError;
use gtk::prelude::*;
use gtk::{glib, Application, ApplicationWindow, Button, Label, ListBox, ListBoxRow};
use gtk4 as gtk;
use gtk4::Entry;

#[allow(unused_imports)]
use crypto_layer::common::{
    crypto::{
        algorithms::{
            encryption::{AsymmetricEncryption, BlockCiphers, EccCurves, EccSchemeAlgorithm},
            hashes::Hash,
            KeyBits,
        },
        KeyUsage,
    },
    traits::{key_handle::KeyHandle, module_provider::Provider},
};

use crypto_layer::hsm::{yubikey::YubiKeyProvider, HsmProviderConfig};

#[cfg(feature = "yubi")]

static mut SIGNATURE: Vec<Vec<u8>> = Vec::new();
static mut ENCRYPTED_DATA: Vec<Vec<u8>> = Vec::new();

fn main() -> glib::ExitCode {
    let application = Application::builder()
        .application_id("com.example.DemoApp")
        .build();

    application.connect_activate(|app| {
        let window = ApplicationWindow::builder()
            .application(app)
            .title("Overview")
            .default_width(500)
            .default_height(400)
            .build();

        let list_box = ListBox::new();
        let actions = vec![
            "Generate Key Pair",
            "Encrypt Data",
            "Decrypt Data",
            "Sign Data",
            "Verify Signature",
        ];

        for action in actions {
            let label = Label::new(Some(action));
            let row = ListBoxRow::new();
            row.set_child(Some(&label));
            list_box.append(&row);
        }

        let app_clone = app.clone();

        list_box.connect_row_activated(move |_, row| {
            let index = row.index();
            match index {
                0 => create_new_window(&app_clone, "Generate Key Pair".to_string()),
                1 => create_new_window(&app_clone, "Encrypt Data".to_string()),
                2 => create_new_window(&app_clone, "Decrypt Data".to_string()),
                3 => create_new_window(&app_clone, "Sign Data".to_string()),
                4 => create_new_window(&app_clone, "Verify Signature".to_string()),
                _ => {}
            }
        });

        let vbox = gtk::Box::new(gtk::Orientation::Vertical, 5);
        vbox.append(&list_box);

        window.set_child(Some(&vbox));
        window.present();
    });

    application.run()
}

fn create_new_window(app: &Application, title: String) {
    if title == "Decrypt Data" {
        let new_window = ApplicationWindow::builder()
            .application(app)
            .title(title.clone())
            .default_width(400)
            .default_height(300)
            .build();

        let vbox = gtk::Box::new(gtk::Orientation::Vertical, 5);
        vbox.set_spacing(5);

        let label_key_id = Label::new(Some("Key ID:"));
        let entry_key_id = Entry::new();
        let entry_key_id_clone = entry_key_id.clone();

        let label_encryption_type = Label::new(Some("Verschlüsselungsart wählen:"));
        let combo_encryption_type = gtk::ComboBoxText::new();
        combo_encryption_type.append(None, "RSA1024");
        combo_encryption_type.append(None, "RSA2048");
        combo_encryption_type.set_active(Some(0));
        let combo_encryption_type_clone = combo_encryption_type.clone();

        let button = Button::with_label("Aktion ausführen");
        let app2 = app.clone();
        button.connect_clicked(move |_| {
            let key_id = entry_key_id.text().to_string();
            let data = "";
            let encryption_type = combo_encryption_type.active_text().unwrap().to_string();
            perform_action(&app2, &title, &data, &key_id, &encryption_type);
        });

        vbox.append(&label_key_id);
        vbox.append(&entry_key_id_clone);
        vbox.append(&label_encryption_type);
        vbox.append(&combo_encryption_type_clone);
        vbox.append(&button);

        new_window.set_child(Some(&vbox));
        new_window.present();
    } else if title == "Encrypt Data" {
        let new_window = ApplicationWindow::builder()
            .application(app)
            .title(title.clone())
            .default_width(400)
            .default_height(300)
            .build();

        let vbox = gtk::Box::new(gtk::Orientation::Vertical, 5);
        vbox.set_spacing(5);

        let label_key_id = Label::new(Some("Key ID:"));
        let entry_key_id = Entry::new();
        let entry_key_id_clone = entry_key_id.clone();

        let label_data = Label::new(Some("Daten:"));
        let entry_data = Entry::new();
        let entry_data_clone = entry_data.clone();

        let label_encryption_type = Label::new(Some("Verschlüsselungsart wählen:"));
        let combo_encryption_type = gtk::ComboBoxText::new();
        combo_encryption_type.append(None, "RSA1024");
        combo_encryption_type.append(None, "RSA2048");
        combo_encryption_type.set_active(Some(0));
        let combo_encryption_type_clone = combo_encryption_type.clone();

        let button = Button::with_label("Aktion ausführen");
        let app2 = app.clone();
        button.connect_clicked(move |_| {
            let key_id = entry_key_id.text().to_string();
            let data = entry_data.text().to_string();
            let encryption_type = combo_encryption_type.active_text().unwrap().to_string();
            perform_action(&app2, &title, &data, &key_id, &encryption_type);
        });

        vbox.append(&label_key_id);
        vbox.append(&entry_key_id_clone);
        vbox.append(&label_data);
        vbox.append(&entry_data_clone);
        vbox.append(&label_encryption_type);
        vbox.append(&combo_encryption_type_clone);
        vbox.append(&button);

        new_window.set_child(Some(&vbox));
        new_window.present();
    } else if title != "Generate Key Pair" {
        let new_window = ApplicationWindow::builder()
            .application(app)
            .title(title.clone())
            .default_width(400)
            .default_height(300)
            .build();

        let vbox = gtk::Box::new(gtk::Orientation::Vertical, 5);
        vbox.set_spacing(5);

        let label_key_id = Label::new(Some("Key ID:"));
        let entry_key_id = Entry::new();
        let entry_key_id_clone = entry_key_id.clone();

        let label_data = Label::new(Some("Daten:"));
        let entry_data = Entry::new();
        let entry_data_clone = entry_data.clone();

        let label_encryption_type = Label::new(Some("Verschlüsselungsart wählen:"));
        let combo_encryption_type = gtk::ComboBoxText::new();
        combo_encryption_type.append(None, "RSA1024");
        combo_encryption_type.append(None, "RSA2048");
        combo_encryption_type.append(None, "ECC256");
        combo_encryption_type.append(None, "ECC384");
        combo_encryption_type.set_active(Some(0));
        let combo_encryption_type_clone = combo_encryption_type.clone();

        let button = Button::with_label("Aktion ausführen");
        let app2 = app.clone();
        button.connect_clicked(move |_| {
            let key_id = entry_key_id.text().to_string();
            let data = entry_data.text().to_string();
            let encryption_type = combo_encryption_type.active_text().unwrap().to_string();
            perform_action(&app2, &title, &data, &key_id, &encryption_type);
        });

        vbox.append(&label_key_id);
        vbox.append(&entry_key_id_clone);
        vbox.append(&label_data);
        vbox.append(&entry_data_clone);
        vbox.append(&label_encryption_type);
        vbox.append(&combo_encryption_type_clone);
        vbox.append(&button);

        new_window.set_child(Some(&vbox));
        new_window.present();
    } else {
        let new_window = ApplicationWindow::builder()
            .application(app)
            .title(title.clone())
            .default_width(400)
            .default_height(300)
            .build();

        let vbox = gtk::Box::new(gtk::Orientation::Vertical, 5);
        vbox.set_spacing(5);

        let label_key_id = Label::new(Some("Key ID:"));
        let entry_key_id = Entry::new();
        let entry_key_id_clone = entry_key_id.clone();

        let label_encryption_type = Label::new(Some("Welchen Schlüssel wollen sie generieren?"));
        let combo_encryption_type = gtk::ComboBoxText::new();
        combo_encryption_type.append(None, "RSA1024");
        combo_encryption_type.append(None, "RSA2048");
        combo_encryption_type.append(None, "ECC256");
        combo_encryption_type.append(None, "ECC384");
        combo_encryption_type.set_active(Some(0));
        let combo_encryption_type_clone = combo_encryption_type.clone();

        let button = Button::with_label("Generieren");
        let app2 = app.clone();

        let data = " ";

        button.connect_clicked(move |_| {
            let key_id = entry_key_id.text().to_string();
            let encryption_type = combo_encryption_type.active_text().unwrap().to_string();
            perform_action(&app2, &title, &data, &key_id, &encryption_type);
        });

        vbox.append(&label_key_id);
        vbox.append(&entry_key_id_clone);
        vbox.append(&label_encryption_type);
        vbox.append(&combo_encryption_type_clone);
        vbox.append(&button);

        new_window.set_child(Some(&vbox));
        new_window.present();
    }
}

fn perform_action(
    app: &Application,
    action: &str,
    data: &str,
    key_id: &str,
    encryption_type: &str,
) {
    match action {
        "Encrypt Data" => {
            let ergebnis = encrypt_data(app, data, key_id, encryption_type);
            match ergebnis {
                Ok(encrypt) => {
                    let value = encrypt;
                    unsafe { ENCRYPTED_DATA.push(value) };
                    let ausgabe = "Successfully encrypted";
                    create_new_window2(app, ausgabe.to_string());
                }
                Err(_) => {
                    let ausgabe = "The data could not be encrypted";
                    create_new_window2(app, ausgabe.to_string());
                }
            }
        }
        "Decrypt Data" => {
            let encrypted = unsafe { ENCRYPTED_DATA.clone() };
            let mut counter = 0;
            for encrypt in encrypted {
                let encrypt = encrypt.as_slice();
                let ergebnis = decrypt_data(app, encrypt, key_id, encryption_type);
                match ergebnis {
                    Ok(erg) => {
                        let ausgabe = format!("The decrypted data is: {}", erg.to_string());
                        create_new_window2(app, ausgabe.to_string());
                        counter = counter + 1;
                    }
                    Err(_) => {}
                }
            }
            if counter == 0 {
                let ausgabe = "The data could not be decrypted";
                create_new_window2(app, ausgabe.to_string());
            }
        }
        "Generate Key Pair" => {
            generate(app, encryption_type, key_id);
        }
        "Sign Data" => {
            let ergebnis = sign_data(app, data, key_id, encryption_type);
            match ergebnis {
                Ok(signat) => {
                    let value = signat;
                    unsafe { SIGNATURE.push(value) };
                    let ausgabe = "Successfully signed";
                    create_new_window2(app, ausgabe.to_string());
                }
                Err(_) => {
                    let ausgabe = "Signature couldn´t be created";
                    create_new_window2(app, ausgabe.to_string());
                }
            }
        }
        "Verify Signature" => {
            let signature = unsafe { SIGNATURE.clone() };
            let mut counter = 0;
            for signat in signature {
                let ergebnis = verify_signature(app, data, key_id, encryption_type, signat);
                match ergebnis {
                    Ok(_) => {
                        let ausgabe = "Successfully verified signature";
                        create_new_window2(app, ausgabe.to_string());
                        counter = counter + 1;
                    }
                    Err(_) => {}
                }
            }
            if counter == 0 {
                let ausgabe = "Signature couldn´t be verified";
                create_new_window2(app, ausgabe.to_string());
            }
        }
        _ => {}
    }
}

fn verify_signature(
    app: &Application,
    data: &str,
    key_id: &str,
    encryption_type: &str,
    signature: Vec<u8>,
) -> Result<(), SecurityModuleError> {
    let mut provider = YubiKeyProvider::new(key_id.to_string());
    let mut config = HsmProviderConfig::new(AsymmetricEncryption::Rsa(KeyBits::Bits1024));
    match encryption_type {
        "RSA1024" => {
            config = HsmProviderConfig::new(AsymmetricEncryption::Rsa(KeyBits::Bits1024));
        }
        "RSA2048" => {
            config = HsmProviderConfig::new(AsymmetricEncryption::Rsa(KeyBits::Bits2048));
        }
        "ECC256" => {
            config = HsmProviderConfig::new(AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(
                EccCurves::P256,
            )));
        }
        "ECC384" => {
            config = HsmProviderConfig::new(AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(
                EccCurves::P384,
            )));
        }
        _ => {}
    }

    let initial = provider.initialize_module();
    match initial {
        Ok(_) => {}
        Err(_) => {
            let ausgabe = "Failed to initialize module";
            create_new_window2(app, ausgabe.to_string());
        }
    }

    let load = provider.load_key(key_id, config);
    match load {
        Ok(_) => {}
        Err(_) => {
            let ausgabe = "Failed to laod key";
            create_new_window2(app, ausgabe.to_string());
        }
    }

    let signature = signature.as_slice();
    let data = data.trim().as_bytes();
    let verify = provider.verify_signature(data, &signature);
    match verify {
        Ok(_) => Ok(()),
        Err(err) => {
            return Err(SecurityModuleError::SignatureVerificationError(
                err.to_string(),
            ))
        }
    }
}

fn sign_data(
    app: &Application,
    data: &str,
    key_id: &str,
    encryption_type: &str,
) -> Result<Vec<u8>, SecurityModuleError> {
    let mut provider = YubiKeyProvider::new(key_id.to_string());
    let mut config = HsmProviderConfig::new(AsymmetricEncryption::Rsa(KeyBits::Bits1024));
    match encryption_type {
        "RSA1024" => {
            config = HsmProviderConfig::new(AsymmetricEncryption::Rsa(KeyBits::Bits1024));
        }
        "RSA2048" => {
            config = HsmProviderConfig::new(AsymmetricEncryption::Rsa(KeyBits::Bits2048));
        }
        "ECC256" => {
            config = HsmProviderConfig::new(AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(
                EccCurves::P256,
            )));
        }
        "ECC384" => {
            config = HsmProviderConfig::new(AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(
                EccCurves::P384,
            )));
        }
        _ => {}
    }

    let initial = provider.initialize_module();
    match initial {
        Ok(_) => {}
        Err(_) => {
            let ausgabe = "Failed to initialize module";
            create_new_window2(app, ausgabe.to_string());
        }
    }

    let load = provider.load_key(key_id, config);
    match load {
        Ok(_) => {}
        Err(_) => {
            let ausgabe = "Failed to laod key";
            create_new_window2(app, ausgabe.to_string());
        }
    }
    let data: &[u8] = data.trim().as_bytes();
    let signature = provider.sign_data(data);
    match signature {
        Ok(sign) => Ok(sign),
        Err(err) => {
            return Err(SecurityModuleError::SignatureVerificationError(
                err.to_string(),
            ))
        }
    }
}

fn create_new_window2(app: &Application, message: String) {
    let new_window = ApplicationWindow::builder()
        .application(app)
        .title("Nachricht")
        .default_width(400)
        .default_height(300)
        .build();

    let vbox = gtk::Box::new(gtk::Orientation::Vertical, 5);
    vbox.set_spacing(5);

    let label_message = Label::new(Some(&message));
    vbox.append(&label_message);

    new_window.set_child(Some(&vbox));
    new_window.present();
}

fn generate(app: &Application, encryption_type: &str, key_id: &str) {
    let mut provider = YubiKeyProvider::new(key_id.to_string());
    let mut config = HsmProviderConfig::new(AsymmetricEncryption::Rsa(KeyBits::Bits1024));
    match encryption_type {
        "RSA1024" => {
            config = HsmProviderConfig::new(AsymmetricEncryption::Rsa(KeyBits::Bits1024));
        }
        "RSA2048" => {
            config = HsmProviderConfig::new(AsymmetricEncryption::Rsa(KeyBits::Bits2048));
        }
        "ECC256" => {
            config = HsmProviderConfig::new(AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(
                EccCurves::P256,
            )));
        }
        "ECC384" => {
            config = HsmProviderConfig::new(AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(
                EccCurves::P384,
            )));
        }
        _ => {}
    }

    let initial = provider.initialize_module();
    match initial {
        Ok(_) => {}
        Err(_) => {
            let ausgabe = "Failed to initialize module";
            create_new_window2(app, ausgabe.to_string());
        }
    }

    match encryption_type {
        "RSA1024" => {
            let rsa = provider.create_key(key_id, config);
            match rsa {
                Ok(_) => {
                    let ausgabe = "Successfully generated RSA1024 key";
                    create_new_window2(app, ausgabe.to_string());
                }
                Err(_) => {
                    let ausgabe = "Failed to generate RSA1024 key";
                    create_new_window2(app, ausgabe.to_string());
                }
            }
        }
        "RSA2048" => {
            let rsa = provider.create_key(key_id, config);
            match rsa {
                Ok(_) => {
                    let ausgabe = "Successfully generated RSA2048 key";
                    create_new_window2(app, ausgabe.to_string());
                }
                Err(_) => {
                    let ausgabe = "Failed to generate RSA2048 key";
                    create_new_window2(app, ausgabe.to_string());
                }
            }
        }
        "ECC256" => {
            let ecc = provider.create_key(key_id, config);
            match ecc {
                Ok(_) => {
                    let ausgabe = "Successfully generated ECC256 key";
                    create_new_window2(app, ausgabe.to_string());
                }
                Err(_) => {
                    let ausgabe = "Failed to generate ECC256 key";
                    create_new_window2(app, ausgabe.to_string());
                }
            }
        }
        "ECC384" => {
            let ecc = provider.create_key(key_id, config);
            match ecc {
                Ok(_) => {
                    let ausgabe = "Successfully generated ECC384 key";
                    create_new_window2(app, ausgabe.to_string());
                }
                Err(_) => {
                    let ausgabe = "Failed to generate ECC384 key";
                    create_new_window2(app, ausgabe.to_string());
                }
            }
        }
        _ => {}
    }
}

fn encrypt_data(
    app: &Application,
    data: &str,
    key_id: &str,
    encryption_type: &str,
) -> Result<Vec<u8>, SecurityModuleError> {
    let mut provider = YubiKeyProvider::new(key_id.to_string());
    let mut config = HsmProviderConfig::new(AsymmetricEncryption::Rsa(KeyBits::Bits1024));
    match encryption_type {
        "RSA1024" => {
            config = HsmProviderConfig::new(AsymmetricEncryption::Rsa(KeyBits::Bits1024));
        }
        "RSA2048" => {
            config = HsmProviderConfig::new(AsymmetricEncryption::Rsa(KeyBits::Bits2048));
        }
        "ECC256" => {
            config = HsmProviderConfig::new(AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(
                EccCurves::P256,
            )));
        }
        "ECC384" => {
            config = HsmProviderConfig::new(AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(
                EccCurves::P384,
            )));
        }
        _ => {}
    }

    let initial = provider.initialize_module();
    match initial {
        Ok(_) => {}
        Err(_) => {
            let ausgabe = "Failed to initialize module";
            create_new_window2(app, ausgabe.to_string());
        }
    }

    let load = provider.load_key(key_id, config);
    match load {
        Ok(_) => {}
        Err(_) => {
            let ausgabe = "Failed to laod key";
            create_new_window2(app, ausgabe.to_string());
        }
    }

    let encrypted = provider.encrypt_data(data.trim().as_bytes());
    match encrypted {
        Ok(encrypt) => Ok(encrypt),
        Err(err) => {
            return Err(SecurityModuleError::SignatureVerificationError(
                err.to_string(),
            ))
        }
    }
}

fn decrypt_data(
    app: &Application,
    data: &[u8],
    key_id: &str,
    encryption_type: &str,
) -> Result<String, SecurityModuleError> {
    let mut provider = YubiKeyProvider::new(key_id.to_string());
    let mut config = HsmProviderConfig::new(AsymmetricEncryption::Rsa(KeyBits::Bits1024));
    match encryption_type {
        "RSA1024" => {
            config = HsmProviderConfig::new(AsymmetricEncryption::Rsa(KeyBits::Bits1024));
        }
        "RSA2048" => {
            config = HsmProviderConfig::new(AsymmetricEncryption::Rsa(KeyBits::Bits2048));
        }
        "ECC256" => {
            config = HsmProviderConfig::new(AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(
                EccCurves::P256,
            )));
        }
        "ECC384" => {
            config = HsmProviderConfig::new(AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(
                EccCurves::P384,
            )));
        }
        _ => {}
    }

    let initial = provider.initialize_module();
    match initial {
        Ok(_) => {}
        Err(_) => {
            let ausgabe = "Failed to initialize module";
            create_new_window2(app, ausgabe.to_string());
        }
    }

    let load = provider.load_key(key_id, config);
    match load {
        Ok(_) => {}
        Err(_) => {
            let ausgabe = "Failed to laod key";
            create_new_window2(app, ausgabe.to_string());
        }
    }

    let decrypted = provider.decrypt_data(data);
    match decrypted {
        Ok(decrypt) => {
            let decrypt = String::from_utf8(decrypt).unwrap();
            Ok(decrypt)
        }
        Err(err) => {
            return Err(SecurityModuleError::SignatureVerificationError(
                err.to_string(),
            ))
        }
    }
}
