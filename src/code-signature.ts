#!/usr/bin/env -S bun run
// SPDX-License-Identifier: CC-BY-4.0
// This work is licensed under the Creative Commons Attribution 4.0 International (CC BY 4.0) License.
// To view a copy of this license, visit https://creativecommons.org/licenses/by/4.0/
// Author: Andreas Timm
// Repository: https://github.com/andreas-timm/code-signature-ts
// Version: 0.4.0
// @sha256sum 0xe901425d12469ef7e0fdd010e2d158d5398a8a6ae7e1a79bce1f77a6b9d3237b
// @eip191signature 0x3b08f924e994205005312fec95c30e181fb066744ca51a17d122221953cda7e37abec4184e1755385cae7837cea1a6e6f74b3d336484026338bf6d2426e9f9be1c

import { parseArgs } from 'util'
import { hashMessage, recoverAddress, sha256 } from 'viem'
import { english, generateMnemonic, mnemonicToAccount } from 'viem/accounts'
import type { Options, SignResult, VerifyResult, CliOptions } from './types.ts'

export function getFilteredContent(content: string, key: string, prefix: string, replace?: string) {
    let filtered = []
    let value: null | `0x${string}` = null
    const lines = content.split('\n')
    let index
    let line: string

    for (index = 0; index < lines.length; index++) {
        line = lines[index]

        if (value === null && line.match(new RegExp(`^\\s*([*#;"]|${prefix})?\\s*${key} 0x\\S+`))) {
            value = line.match(new RegExp(`${key}\\s+(0x\\S+)`))![1] as `0x${string}`
            if (replace !== undefined) {
                line = line.replace(new RegExp(`(${key}\\s+)\\S+`), `\$1${replace}`)
            } else {
                continue
            }
        }

        filtered.push(line)
    }

    return { content: filtered.join('\n'), value }
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

    let signature: null | `0x${string}`
    let toSha256Content: null | string
    let sha256sum: null | `0x${string}`
    let signedContent: null | string

    signature = await account.signMessage({ message: verifyResult.signFiltered.content })

    if (verifyResult.signFiltered.value !== null) {
        toSha256Content = getFilteredContent(
            verifyResult.content,
            '@eip191signature',
            options.prefix,
            signature,
        ).content
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
    console.log('  --write, -w — write file')
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
        let lines: string[] = []
        for await (const line of console) {
            lines.push(line)
        }
        content = lines.join('\n')
    } else {
        content = await Bun.file(options.filePath).text()
    }

    const verifyResult = await verify(content, options.prefix)
    let signResult: null | SignResult = null
    let fail = true

    if (verifyResult.sha256Valid) {
        if (!options.silent) {
            console.log(`OK: ${verifyResult.address}`)
        }
        fail = false
    }

    if (!options.verify) {
        signResult = await sign(verifyResult, options)

        if (signResult.signedContent !== null) {
            if (options.write && fail) {
                await write(options, signResult.signedContent)
            }

            if (fail && !options.write && !options.silent) {
                console.log(`${options.prefix} @sha256sum ${signResult.sha256sum}`)
                console.log(`${options.prefix} @eip191signature ${signResult.signature}`)
            }
        } else {
            console.log('ERROR: no signed content')
            fail = true
        }
    }

    if (fail && !options.silent) {
        console.log('SHA256: ERROR')
    }

    return { verifyResult, signResult, fail }
}

export async function codeSign() {
    const { values, positionals } = parseArgs({
        args: Bun.argv,
        options: {
            help: { type: 'boolean', short: 'h', default: false },
            write: { type: 'boolean', short: 'w', default: false },
            verify: { type: 'boolean', short: 'v', default: false },
            silent: { type: 'boolean', short: 's', default: false },
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

if (import.meta.main) {
    await codeSign()
}
