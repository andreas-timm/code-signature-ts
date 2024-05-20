# EIP-191 Code Signature (Typescript)

## Motivation
Ensuring the integrity and authenticity of text files, especially source code, makes sense. This module offers a tool to sign text files with an EVM account using EIP-191[^1] signatures, providing an alternative to GPG that is not tied to an email address.

By adding an additional SHA-256 hash, any changes (even slight) to the file after the EIP-191[^1] signature has been added can be detected. This ensures the integrity of the file, preventing issues like incorrect address recovery, which makes sense for applications involving donations, licensing fees, or other transactions. Additionally, the SHA-256 hash can serve as a search key and help confirm the date of the file’s first public availability.

This version maintains the clarity and objectives of your original text while slightly improving the flow and readability.

## Syntax

```ts
// @sha256sum 0xdaea6ea29e60619ef1050287fb380a9edc234c8d18e01103a5fb8027694f91f4
// @eip191signature 0x96958f5875095d4b2967e37dda0b4a696611e2c2fb543ae30be41056f94b97f31d40970caf2ceeec179b2cfe23a7e37a1ef44a817113dc3a368f9296adab93531c
```

## Compatibility
This tool has been developed and tested exclusively on **macOS**. It is not guaranteed to work on other operating systems.

## Limitations
Only comments of the double slash "`//`" type can be used at this time.

## Usage
### Check
```shell
code-signature --verify code-file.ts
OK: 0x0000000000000000000000000000000000000000
```

### Integration with pass/gpt
```shell
MNEMONIC=$(pass show mnemonic) code-signature --write code-file.ts
```

## License
- [LICENSE](https://github.com/andreas-timm/code-signature-ts/blob/main/LICENSE)

This work is licensed under the Creative Commons Attribution 4.0 International (CC BY 4.0) License.
To view a copy of this license, visit https://creativecommons.org/licenses/by/4.0/  
Author: Andreas Timm

## Links
[^1]: https://eips.ethereum.org/EIPS/eip-191
