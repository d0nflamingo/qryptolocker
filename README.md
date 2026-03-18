<div align="center">
  <pre>
 ██████╗ ██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗ 
██╔═══██╗██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔═══██╗
██║   ██║██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║   ██║
██║▄▄ ██║██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║   ██║
╚██████╔╝██║  ██║   ██║   ██║        ██║   ╚██████╔╝
 ╚══▀▀═╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝    ╚═════╝ 
██╗      ██████╗  ██████╗██╗  ██╗███████╗██████╗    
██║     ██╔═══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗   
██║     ██║   ██║██║     █████╔╝ █████╗  ██████╔╝   
██║     ██║   ██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗   
███████╗╚██████╔╝╚██████╗██║  ██╗███████╗██║  ██║   
╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   
  </pre>
</div>

## 🔐 About

`qryptolocker` is a post-quantum cryptography powered file encryption system based on a client-server architecture.

- master key safely stored on the server
- client-server communication secured with post-quantum cryptography
- partial decryption of the arborescence 
- minimal attack surface for memory analysis

### How?
For further informations about the architecture and the key mechanisms, please refer to the [docs/architecture.md](./docs/architecture.md) document.

---

## 🔐 Usage

### Prerequisites
- Rust stable (1.70 or later) - install via [rustup](https://rustup.rs/)

### Installation

```bash
git clone https://github.com/d0nflamingo/qryptolocker
cd qryptolocker
cargo build --release
```

### Running the server

```bash
cargo run -p server --bin qrypto-c2
```

### Running the client

```bash
cargo run -p client
```

---

## ⚠ Security considerations

The use of words for decryption was mandatory for the sake of the initial school project but is obviously a bad practice as it reduces the total number of possibility for the password.

---

## 🚧 Further improvements

- Replace requirement to input password for decryption with automated cryptographic key validation
- Simplify the install and deployment process

---

## Contributing

EVE is MIT licensed - you are free to fork it, adapt it, and use it in any project, including commercial ones. No contribution process is set up at this time.

If you find a bug or have a suggestion, feel free to open an issue

---
## License
MIT - see [LICENSE](./LICENSE) for details.

