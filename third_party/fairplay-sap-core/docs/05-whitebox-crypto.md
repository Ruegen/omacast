# White-box cryptography

The single biggest question a newcomer has about this repo is: *if you reverse
engineered the cipher, why is there still ~300 KB of table data you can't get rid
of?* The answer is what white-box cryptography is, and it is worth understanding
because it bounds how small this can ever be.

## The key is not in the code — it is in the tables

In ordinary AES, there is a key, and the code mixes that key into the data. If you
have the code and the key, you have everything; if you have only the code, you are
missing the key.

White-box AES is designed for a world where the attacker can read all the code and
watch all the memory — the "white box". So it hides the key by **dissolving it
into lookup tables** at build time. Instead of `AES(key, data)`, you get a chain
of table lookups `T₃(T₂(T₁(data)))` where the key has been folded, together with
random encodings, into the contents of `T₁`, `T₂`, `T₃`. There is no separate key
variable anywhere. **The tables are the cipher.**

## Why that means the tables can't be shrunk further

Because the key lives *inside* the table contents, you cannot factor it back out
and store "just the key" plus small code. There is no smaller representation that
still computes the same function without the original key material — which nobody
outside Apple has. The tables are recovered *data*, and recovered data does not
compress the way redundant code does.

This project shrank everything that *was* reducible:

- Every 256-entry byte table turned out to be an XOR-affine image of one of a few
  bases — `T[v] == base[v ^ inXor] ^ outXor` — so **135,168 bytes of table data
  is stored in 5,168** and rebuilt at init.
- A MixColumns matrix that is block-diagonal with four identical blocks: 2,048
  bytes → 128.
- T-boxes whose 16 byte lanes reduce to 4 bases: 4,096 → 1,072.
- An entire 12.9 KB table for a stage (`ApplyStage2`) that had no callers at all,
  deleted outright.

What remains after all of that is the irreducible floor: the base tables that
genuinely encode mode 3's key schedule. They are Apple-derived data, they will
always be here, and there is no smaller form. The rest of the module — the bridge
and Phase 2 — is *algorithm*, and that is why it collapsed from 7.2 MB of
generated code to ~633 lines.

## Why only mode 3

FairPlay defines four message modes, and each uses a different key schedule. A
white-box implementation bakes *one* key schedule into its tables — there is no
runtime parameter that selects a different one, because the key is not a parameter,
it is the table contents. These tables encode mode 3, so this implementation
answers mode 3 and refuses the rest. Supporting another mode would mean recovering
that mode's tables too.

## What this is *not*

The white-box tables here implement the **authentication** cipher. They are not
FairPlay Streaming DRM, they hold no content-decryption key, and running them
extracts nothing from protected media. See [Limitations](09-limitations.md) and
the repository's [`NOTICE.md`](../NOTICE.md).

For how these tables were recovered and verified, see
[How this was derived](10-history.md).
