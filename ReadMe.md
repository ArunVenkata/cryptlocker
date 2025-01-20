# 🦀 Cryptlocker

Cryptlocker is a powerful and easy-to-use command-line tool for encrypting and decrypting files and folders. It ensures your sensitive data remains secure with robust encryption methods. Perfect for safeguarding personal and professional information.


## 🚀 Examples of Usage

Here are some examples of how to use the `cryptlocker` command:

1. Encrypt a file:
```bash
cryptlocker lock /path/to/your/file.txt
```

2. Encrypt a folder:
```bash
cryptlocker lock /path/to/your/folder
```

3. Decrypt a file:
```bash
cryptlocker unlock /path/to/your/file.txt
```

4. Decrypt a folder:
```bash
cryptlocker unlock /path/to/your/folder.zip.cryptic
```


## 📦 Installation Instructions


### Windows
1. Open a Command Prompt with administrative privileges.
2. Run the following command to install `cryptlocker`:

```powershell

powershell -Command "Invoke-WebRequest -Uri https://raw.githubusercontent.com/ArunVenkata/cryptlocker/master/scripts/install.bat -OutFile install.bat; Start-Process -FilePath install.bat -Wait"
```


### Linux/MacOS

1. Open a terminal.

2. Run the following command to install `cryptlocker`

```bash
curl -sSL https://raw.githubusercontent.com/ArunVenkata/cryptlocker/master/scripts/install.sh | sh
```

> Note: To uninstall, Replace the word `install` with `uninstall` in the above commands.

## 🖥️ Install from Source

1. Clone the repository:
```bash
git clone https://github.com/ArunVenkata/cryplocker.git
cd cryptlocker
```
2. Ensure you have [Rust](https://www.rust-lang.org/tools/install) installed on your machine.

3. Build the project:
```bash
cargo build --release
```

4. Run the tool:
```bash
./target/release/cryptlocker help
```

Run `cryptlocker help` for more information on the supported parameters.


## 🤝 Contributing Guidelines

If you would like to contribute to the project, please follow these guidelines:
1. Fork the repository and create your feature branch:

```bash
git checkout -b feature/new-feature
```

2. Commit your changes:

```bash
git commit -m "Add some feature"
```

3. Push to the branch:
```bash
git push origin feature/new-feature
```

4. Open a pull request and describe your changes.



## 🎉 License

This project is licensed under the MIT License. See the [LICENSE](https://www.github.com/ArunVenkata/cryptlocker/blob/master/LICENSE) file for details.

