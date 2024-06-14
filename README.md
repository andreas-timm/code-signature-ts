# EIP-191 Code Signature (Typescript)

[![test](https://github.com/andreas-timm/code-signature-ts/actions/workflows/test.yml/badge.svg)](https://github.com/andreas-timm/code-signature-ts/actions/workflows/test.yml)  

## Motivation
Ensuring the integrity and authenticity of text files, especially source code, makes sense. This module offers a tool to sign text files with an EVM account using EIP-191[^1] signatures, providing an alternative to GPG that is not tied to an email address.

By adding an additional SHA-256 hash, any changes (even slight) to the file after the EIP-191[^1] signature has been added can be detected. This ensures the integrity of the file, preventing issues like incorrect address recovery, which makes sense for applications involving donations, licensing fees, or other transactions. Additionally, the SHA-256 hash can serve as a search key and help confirm the date of the file’s first public availability.

This version maintains the clarity and objectives of your original text while slightly improving the flow and readability.

## Practical Implementation

### Add signature
- **Step 1**: Calculate the EIP-191 signature from the original text.
- **Step 2**: Add the EIP-191 signature as a comment line.
- **Step 3**: Calculate the SHA-256 hash of the entire text, including the EIP-191 signature comment.
- **Step 4**: Add the SHA-256 hash as an additional comment line.

### Verification process
- **Step 1**: Calculate the SHA-256 hash of the current file (including the signature comment, but without the SHA-256 comment) and compare it to the provided SHA-256 hash.
- **Step 2**: Restore EVM account address from EIP-191 signature against the original text hash without the signature comment.

### Example
```ts
// @sha256sum 0xe901425d12469ef7e0fdd010e2d158d5398a8a6ae7e1a79bce1f77a6b9d3237b
// @eip191signature 0x3b08f924e994205005312fec95c30e181fb066744ca51a17d122221953cda7e37abec4184e1755385cae7837cea1a6e6f74b3d336484026338bf6d2426e9f9be1c
```

## Compatibility
This tool has been developed and tested exclusively on **macOS**. It is not guaranteed to work on other operating systems.

## Install
```shell
git clone --depth=1 https://github.com/andreas-timm/code-signature-ts.git ~/.local/share/code-signature-ts
```
```shell
cd ~/.local/share/code-signature-ts
```
```shell
bun install -p
```
```shell
ln -s ~/.local/share/code-signature-ts/src/code-signature.ts ~/.local/bin/code-signature
```

## Usage
### Help
```shell
$ code-signature -h
Usage: code-signature-ts [OPTIONS] <FILE|->
OPTIONS:
  --verify, -v — only verify
  --write, -w — write file
  --silent, -s — silent
  --prefix, -p — commented line prefix
  --out, -o — output file
ENVIRONMENT:
  MNEMONIC — mnemonic
```

### Check
```shell
code-signature -v src/code-signature.ts
OK: 0x630C6C3180d3b4B6912644D046f6769dA3e54843
```

### Integration with pass/gpg
```shell
MNEMONIC=$(pass show mnemonic) code-signature --write code-file.ts
```

## Min version
- [code-signature-min.ts](src/code-signature-min.ts)  
  minified: [build/code-signature-min.js](build/code-signature-min.js)

## Roadmap
- [ ] Add a demonstration static (SSG) frontend.

## License
[![CC BY 4.0][cc-by-shield]][cc-by]

This work is licensed under a [Creative Commons Attribution 4.0 International License][cc-by].

[![CC BY 4.0][cc-by-image]][cc-by]

[cc-by]: http://creativecommons.org/licenses/by/4.0/
[cc-by-image]: https://i.creativecommons.org/l/by/4.0/88x31.png
[cc-by-shield]: https://img.shields.io/badge/License-CC%20BY%204.0-lightgrey.svg

- [LICENSE](https://github.com/andreas-timm/code-signature-ts/blob/main/LICENSE)
- Author: Andreas Timm

## Links
[^1]: https://eips.ethereum.org/EIPS/eip-191
