#!/usr/bin/env -S bun run
// SPDX-License-Identifier: CC-BY-4.0
// This work is licensed under the Creative Commons Attribution 4.0 International (CC BY 4.0) License.
// To view a copy of this license, visit https://creativecommons.org/licenses/by/4.0/
// Author: Andreas Timm
// Repository: https://github.com/andreas-timm/code-signature-ts
// Version: 0.1.0
// @eip191signature 0x9f49a5cc7c79489ec1b37890a2a44be7a27fdffe87856422475ba0b375e1d9b33b98f5b653acf745fa06be45bce5d66da5af3d1c5e06adf0401e977c01cb31171c
// @sha256sum 0xfec11653f8312e10be3ebb2f45251a46c83fd74d811267721c024e2f3ce86842

import { sha256 } from 'viem'
import { english, generateMnemonic, mnemonicToAccount } from 'viem/accounts'

export async function run() {
    const filePath = process.argv[2] ?? process.argv[1]
    const content = await Bun.file(filePath).text()
    const keys = ['eip191signature', 'sha256sum'] as const
    const contentOrig = keys.reduce((acc, k) => acc.replace(new RegExp(`// @${k} \\S+\n`), ''), content)
    let mnemonic = process.env.MNEMONIC
    if (!mnemonic) {
        mnemonic = generateMnemonic(english, 256)
        console.log(mnemonic)
    }

    const signature = await mnemonicToAccount(mnemonic).signMessage({ message: contentOrig })
    let updatedContent = content.replace(new RegExp(`// @${keys[0]} \\S+`), `// @${keys[0]} ${signature}`)
    let updatedData = {
        eip191signature: signature,
        sha256sum: sha256(new TextEncoder().encode(updatedContent.replace(new RegExp(`// @${keys[1]} \\S+\n`), ''))),
    }
    updatedContent = updatedContent.replace(
        new RegExp(`// @${keys[1]} \\S+`),
        `// @${keys[1]} ${updatedData.sha256sum}`,
    )

    const match = content.match(new RegExp(`@(${keys.join('|')}) (\\S+)`, 'g'))
    if (match) {
        const data = Object.fromEntries((match as string[]).splice(0, 2).map((item) => item.slice(1).split(' ')))
        const success = keys.reduce((acc: boolean, k: (typeof keys)[number]) => {
            if (data[k] !== updatedData[k]) {
                console.log(`// @${k} ${updatedData[k]}`)
                acc = false
            }
            return acc
        }, true)
        if (success) {
            console.log('OK')
            return
        }
        await Bun.write(filePath, updatedContent)
    }
}

import.meta.main && run().then()
