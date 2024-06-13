#!/usr/bin/env -S bun run
// SPDX-License-Identifier: CC-BY-4.0
// This work is licensed under the Creative Commons Attribution 4.0 International (CC BY 4.0) License.
// To view a copy of this license, visit https://creativecommons.org/licenses/by/4.0/
// Author: Andreas Timm
// Repository: https://github.com/andreas-timm/code-signature-ts
// Version: 0.3.0
// @sha256sum 0x904d8038d8a3ae6144e5b4275c5f5c76b3d28bddf574ada8cc394fb091a3e2c5
// @eip191signature 0x6b55e4c5241cf7824a70f3f971b16be497ad5e2d808daca00280c975a5604a396a2fdfcf5d30d6f7c15c84a4f5a44d813311d7231acc7b2041a1aa20574e8c851b

import { parseArgs } from 'util'
import { hashMessage, recoverAddress, sha256 } from 'viem'
import { english, generateMnemonic, mnemonicToAccount } from 'viem/accounts'
import type { Options, SignResult, VerifyResult, CliOptions } from './types.ts'

export function splitIndexLines(content: string) {
    return content.split(/(\n+)/).reduce((acc: string[][], part: string, index: number) => {
        if (index % 2 === 0) {
            acc.push([part])
        } else {
            acc[acc.length - 1].push(part)
        }
        return acc
    }, [])
}

export function getFilteredContent(content: string, key: string, prefix: string, replace?: string) {
    const lines = splitIndexLines(content)
    let filtered = []
    let value: null | `0x${string}` = null
    let index

    for (index = 0; index < lines.length; index++) {
        if (lines[index][0].match(new RegExp(`^\\s*([*#;"]|${prefix})?\\s*` + key))) {
            value = lines[index][0].match(new RegExp(`${key}\\s+(\\S+)`))![1] as `0x${string}`
            if (replace !== undefined) {
                filtered.push(
                    [
                        lines[index][0].replace(new RegExp(`(${key}\\s+)\\S+`), `\$1${replace}`),
                        lines[index][1],
                    ].join(''),
                )
            }
            filtered = filtered.concat(lines.splice(index + 1).map((line) => line.join('')))
            break
        }

        filtered.push(lines[index].join(''))
    }

    return { content: filtered.join(''), value }
}

export async function verify(content: string, prefix: string): Promise<VerifyResult> {
    const sha256Filtered = getFilteredContent(content, '@sha256sum', prefix)
    const signFiltered = getFilteredContent(sha256Filtered.content, '@eip191signature', prefix)
    const sha256sum = sha256(new TextEncoder().encode(sha256Filtered.content))

    const address =
        signFiltered.value !== null
            ? await recoverAddress({
                  hash: hashMessage(signFiltered.content),
                  signature: signFiltered.value,
              })
            : null

    return {
        content,
        sha256Filtered,
        signFiltered,
        sha256sum,
        sha256Valid: sha256Filtered.value === sha256sum,
        address,
    }
}

export async function sign(verifyResult: VerifyResult, options: Options): Promise<SignResult> {
    let showAddress = false
    if (options.mnemonic === undefined) {
        options.mnemonic = generateMnemonic(english, 256)
        console.log('Generated mnemonic:', options.mnemonic)
        showAddress = true
    }

    const account = mnemonicToAccount(options.mnemonic)
    if (showAddress) {
        console.log('Address:', account.address)
    }

    let valid = account.address === verifyResult.address
    let signature: null | `0x${string}` = null
    let toSha256Content: null | string = null
    let sha256sum: null | `0x${string}` = null
    let signedContent: null | string = null

    if (!valid || !verifyResult.sha256Valid) {
        signature = await account.signMessage({ message: verifyResult.signFiltered.content })

        if (verifyResult.signFiltered.value !== null) {
            toSha256Content = getFilteredContent(verifyResult.content, '@eip191signature', options.prefix, signature).content
        } else {
            toSha256Content = [`${options.prefix} @eip191signature ` + signature, verifyResult.content].join('\n')
        }

        sha256sum = sha256(
            new TextEncoder().encode(getFilteredContent(toSha256Content, '@sha256sum', options.prefix).content),
        )

        if (verifyResult.sha256Filtered.value !== null) {
            signedContent = getFilteredContent(toSha256Content, '@sha256sum', options.prefix, sha256sum).content
        } else {
            signedContent = [`${options.prefix} @sha256sum ` + sha256sum, toSha256Content].join('\n')
        }
    }

    return {
        address: account.address,
        signature,
        toSha256Content,
        sha256sum,
        signedContent,
    } as SignResult
}

function printHelp() {
    console.log('Usage: code-signature-ts [OPTIONS] <FILE|->')
    console.log('OPTIONS:')
    console.log('  --verify, -v — only verify')
    console.log('  --write, -f — write file')
    console.log('  --silent, -s — silent')
    console.log('  --prefix, -p — commented line prefix')
    console.log('  --out, -o — output file')
    console.log('ENVIRONMENT:')
    console.log('  MNEMONIC — mnemonic')
}

export async function write(options: Options, content: string) {
    const filePath = options.out ?? options.filePath

    if (filePath === undefined) {
        console.log(content)
    } else {
        await Bun.write(filePath, content)

        if (!options.silent) {
            console.log('Wrote:', filePath)
        }
    }
}

export async function codeSignature(options: Options) {
    let content: string

    if (options.filePath == '-') {
        content = ''
    } else {
        content = await Bun.file(options.filePath).text()
    }

    const verifyResult = await verify(content, options.prefix)
    let signResult: null | SignResult = null
    let fail = false

    if (verifyResult.sha256Valid) {
        if (!options.silent) {
            console.log(`OK: ${verifyResult.address}`)
        }
    } else if (!options.verify) {
        signResult = await sign(verifyResult, options)

        if (signResult.signedContent === null) {
            console.log('ERROR: no signed content')
            fail = true
        } else if (options.write) {
            await write(options, signResult.signedContent)
        } else if (!options.silent) {
            console.log(`${options.prefix} @sha256sum ${signResult.sha256sum}`)
            console.log(`${options.prefix} @eip191signature ${signResult.signature}`)
        }
    } else {
        if (!options.silent) {
            console.log('SHA256: ERROR')
        }
        fail = true
    }

    return { verifyResult, signResult, fail }
}

if (import.meta.main) {
    const {values, positionals} = parseArgs({
        args: Bun.argv,
        options: {
            help: { type: 'boolean', short: 'h' },
            write: { type: 'boolean', short: 'w' },
            verify: { type: 'boolean', short: 'v' },
            silent: { type: 'boolean', short: 's' },
            prefix: { type: 'string', short: 'p', default: '//' },
            out: { type: 'string', short: 'o' },
        },
        strict: true,
        allowPositionals: true,
    })
    const cliOptions: CliOptions = values as CliOptions

    if (values.help) {
        printHelp()
        process.exit(0)
    }

    if (positionals.length < 3) {
        printHelp()
        process.exit(1)
    }

    const mnemonic = process.env.MNEMONIC

    const res = await codeSignature({ filePath: positionals[2], ...cliOptions, mnemonic })

    if (res.fail) {
        process.exit(1)
    }
}
