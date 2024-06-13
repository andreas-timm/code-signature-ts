import type { Address } from 'viem'

export type CliOptions = {
    help?: boolean,
    write?: boolean,
    verify?: boolean,
    silent?: boolean,
    prefix: string,
    out?: string,
}

export type Options = CliOptions & {
    filePath: string
    mnemonic?: string
}

export type VerifyResult = {
    content: string
    sha256Filtered: {
        content: string
        value: null | `0x${string}`
    }
    signFiltered: {
        content: string
        value: null | `0x${string}`
    }
    sha256Valid: boolean
    sha256sum: null | `0x${string}`
    address: null | Address
}

export type SignResult = {
    originContent: string
    address: Address
    signature: null | `0x${string}`
    toSha256Content: null | string
    sha256sum: null | `0x${string}`
    signedContent: null | string
}
