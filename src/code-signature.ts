#!/usr/bin/env -S bun run
// SPDX-License-Identifier: CC-BY-4.0
// This work is licensed under the Creative Commons Attribution 4.0 International (CC BY 4.0) License.
// To view a copy of this license, visit https://creativecommons.org/licenses/by/4.0/
// Author: Andreas Timm
// Repository: https://github.com/andreas-timm/code-signature-ts
// Version: 0.2.0
// @sha256sum 0xdaea6ea29e60619ef1050287fb380a9edc234c8d18e01103a5fb8027694f91f4
// @eip191signature 0x96958f5875095d4b2967e37dda0b4a696611e2c2fb543ae30be41056f94b97f31d40970caf2ceeec179b2cfe23a7e37a1ef44a817113dc3a368f9296adab93531c

import { parseArgs } from 'util'
import { hashMessage, recoverAddress, sha256 } from 'viem'
import { english, generateMnemonic, mnemonicToAccount } from 'viem/accounts'
import type { Options, SignResult, VerifyResult } from './types.ts'

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

export function getFilteredContent(content: string, key: string, replace?: string) {
    const lines = splitIndexLines(content)
    let filtered = []
    let value: null | `0x${string}` = null
    let index

    for (index = 0; index < lines.length; index++) {
        if (lines[index][0].match(new RegExp('^\\s*([*#;"]|//)?\\s*' + key))) {
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

export async function verify(content: string): Promise<VerifyResult> {
    const sha256Filtered = getFilteredContent(content, '@sha256sum')
    const signFiltered = getFilteredContent(sha256Filtered.content, '@eip191signature')
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
            toSha256Content = getFilteredContent(verifyResult.content, '@eip191signature', signature).content
        } else {
            toSha256Content = ['// @eip191signature ' + signature, verifyResult.content].join('\n')
        }

        sha256sum = sha256(
            new TextEncoder().encode(getFilteredContent(toSha256Content, '@sha256sum').content),
        )

        if (verifyResult.sha256Filtered.value !== null) {
            signedContent = getFilteredContent(toSha256Content, '@sha256sum', sha256sum).content
        } else {
            signedContent = ['// @sha256sum ' + sha256sum, toSha256Content].join('\n')
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

    const verifyResult = await verify(content)
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
            console.log(`// @sha256sum ${signResult.sha256sum}`)
            console.log(`// @eip191signature ${signResult.signature}`)
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
    const { values, positionals } = parseArgs({
        args: Bun.argv,
        options: {
            help: { type: 'boolean', short: 'h' },
            write: { type: 'boolean', short: 'w' },
            verify: { type: 'boolean', short: 'v' },
            silent: { type: 'boolean', short: 's' },
            out: { type: 'string', short: 'o' },
        },
        strict: true,
        allowPositionals: true,
    })

    if (values.help) {
        printHelp()
        process.exit(0)
    }

    if (positionals.length < 3) {
        printHelp()
        process.exit(1)
    }

    const mnemonic = process.env.MNEMONIC

    const res = await codeSignature({ filePath: positionals[2], ...values, mnemonic })

    if (res.fail) {
        process.exit(1)
    }
}
