> This project was for [Hack Club](https://hackclub.com)'s Summer of Making challenge.

# apple_generative_model_safety_decrypted

This dev log describes the process I took to determine how the files were encrypted and how to find the key.

## First discovery

I first found all the metadata.json.enc files while searching through the AssetsV2 directory in /System/Library. Opening them in a hex editor revealed completely random data, not resembling JSON at all. The .enc extension was a clear indicator that these files were encrypted. 

## DTrace to the rescue

To figure out what processes were reading the encrypted files, I threw together a DTrace script (using the D programming language) which logs a PID and backtrace of any open/openat syscalls that happen whose paths include `metadata.json.enc`. This was extremely valuable in helping me find the right starting point while reversing the rest of the system. 

## GenerativeExperiencesSafetyInferenceProvider

This process is the one I discovered to be reading the encrypted files, so it's where I started. Opening the binary in my static analysis tool of choice, in common Apple fashion, it simply calls out to a function from a private framework in the DYLD shared cache: ModelCatalog. So then I proceeded to load that module into the cache.

### A note on offsets

One slightly irritating thing about the DYLD shared cache is that when loaded into memory, everything is slightly shifted. The offset a segment in the shared cache lists for its __TEXT__ section isn't the true offset in memory. To fix this, you have to take an address (either from IDA or in memory), subtract the base (corresponding to the current environment), and add the other base. It is a minor thing but doing it a lot is very annoying.

## ModelCatalog

After finding the offset of ModelCatalog in memory using LLDB, and referencing the backtrace from my DTrace script, I located the function which was reading the encrypted JSON files. Funnily enough, the symbols here hadn't been stripped, and the function was named Obfuscation.readObfuscatedContents

## readObfuscatedContents

The function wasn't that simple, though, especially without any extra symbol or debugging info. IDA's Swift support is heavily lacking, so the decompiler view missed many code paths; meaning I had to work in assembly.

If you've ever reverse engineered Swift code before, you'll know that it is much more difficult to work with than Objective-C. Despite the fact that Swift has runtime metadata to support reflection and other language features, many times this metadata is extremely hard to understand or fully nonexistent (some struct types have functions which set/get values rather than an offset table which makes it nearly impossible to find the offset of fields without looking at hundreds of subroutines).

This function was no exception, and I still don't understand some parts. However, the general flow of the code works like:

- The code appends .enc to the passed in URL
- A Data object is created for the JSONDecoder
- The path is passed to the deobfuscation
   function, which returns a Data object 
   containing the decrypted JSON
- Error handling and fallback file stuff...
- JSONDecoder is initialized and fed
   the input type to decode to along 
   with the new Data object
- Returns the result of the JSONDecoder

## Deobfuscation function

This function was the most difficult to reverse, and it was made to be difficult to analyze (in fact, I still don't understand how part of it works). Essentially, it gets random data from `swift_stdlib_random` and XORs it with some constants to produce a 32-byte key. Then CryptoKit is used to make a SealedBox around the data object passed in (which contains a nonce and auth value), and the AES256-GCM algorithm is used to decrypt this with the generated key.

> I came back to this later to figure it out. Turns out that the random value is XORed with a constant key and then small parts of it are shuffled around and re-XORed, cancelling out the randomness.

## Back to readObfuscatedContents

Seeing that I was stuck on my key generation analysis-- which I would inevitably use to reimplement it in Python (or possibly C) in order to get a key which I could decrypt stuff with-- I hacked together a temporary solution in the form of an LLDB script setting breakpoints at two points to retrieve the decrypted data manually:

1. Near the beginning of the function when the input URL is ready so I could save the decrypted file contents in a similar path somewhere local (mimicking the original path)

2. Before the JSONDecoder is fed the decrypted data so I could manually parse the structure (Data* + 0x10 is a pointer to the string, Data* + 0x18 is a 64-bit integer encoding the string length) and extract the decrypted data.

## Seeking a better solution

The issue with that solution is that readObfuscatedContents is called lazily only when a safety rule is needed (for example on generation, which up until this point I had been triggering using a project in Xcode using the newly introduced Foundation Models framework). So I was only able to extract *some* of the safety files, not all of them. I would need to get the actual decryption key to decrypt the rest.

## 

Up until this point, I had been using LLVM's LLDB (not intentionally, it just came first in my path), which did not have Swift support. To easily manipulate the Data, SealedBox, and SymmetricKey structures (which are all non-private and available normally in Swift with an import), I needed to use the Swift version of LLDB shipped with Xcode. This was easy to solve, it's just a matter of prefixing my LLDB command with xcrun, which locates the Xcode version of a program.

## Open sesame

After looking at Apple's CryptoKit documentation, I determined that `static func CryptoKit.AES.GCM.open(_ sealedBox: AES.GCM.SealedBox, using key: SymmetricKey) throws -&gt; Data` was the best target to retrieve the key. With the Swift version of LLDB at my side, I could simply set a breakpoint on this function, and using the Swift interpreter, cast the pointer in register x0 to a SymmetricKey structure and retrieve the value using the .withUnsafeBytes function. It is important to note that the breakpoint cannot be directly at the entry, as the first 10 or so instructions are responsible for cleaning up the type info and preparing for accesses, so if you try and cast x0 before those run, you get garbage data. I wrote a small LLDB script which sets the breakpoint and retrieves (and saves) the key automagically.

## The end

After getting the key, I wrote a Python script to find all the encrypted JSON files and decrypt them and save the decrypted versions locally. This was the most trivial part of the whole process. I also uploaded the decrypted version of GitHub for anyone to reference, though I do warn you that some of the filters have nasty words in them: [GitHub repository](https://github.com/BlueFalconHD/apple_generative_model_safety_decrypted).

## Further questions
The only thing I really need to still figure out is the weird key generation song and dance, but that isn't an immediate concern.

## Thanks

Thanks for taking interest in my efforts. If you have any things you'd like me to try my hand at reverse engineering, give me a shout on the Hack Club Slack @BlueFalconHD
