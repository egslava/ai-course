module source.sha256;

import std.ascii, std.exception, std.range, std.string, std.traits, std.bitmanip, std.algorithm;
import std.c.string;

package:


immutable uint[64] k256 = [
   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

// function that translates to ror
uint rotr(in uint value, in uint shift) @safe pure nothrow{
    return (value >> shift) | (value << (32 - shift));
}

ulong rotr(in ulong value, in uint shift) @safe pure nothrow{
    return (value >> shift) | (value << (64 - shift));
}

// function that translates to rol
uint rotl(in uint value, in uint shift) @safe pure nothrow{
    return (value << shift) | (value >> (32 - shift));
}

ulong rotl(in ulong value, in uint shift) @safe pure nothrow{
    return (value << shift) | (value >> (64 - shift));
}

// for CTFE
void setByte(A)(ref A a, size_t offset, ubyte value) @trusted pure nothrow
    if (isArray!A){
    if (__ctfe){
        alias ElementType!A E;
        a[offset / E.sizeof] |= value << ((offset % E.sizeof) * 8);
    }else{
        (cast(ubyte[])a)[offset] = value;
    }
}

ubyte getByte(A)(ref A a, size_t offset) pure nothrow
    if (isArray!A){
    alias ElementType!A E;
    return a[offset / E.sizeof] >> ((offset % E.sizeof) * 8) & 0xFF;
}

ubyte getByte(T)(T t, size_t offset) pure nothrow
    if (isIntegral!T){
    return t >> (offset * 8) & 0xFF;
}

void memCopy(Dst, Src)(ref Dst dst, size_t dstOffset, in Src src, size_t srcOffset, size_t length) @trusted pure nothrow
    if ((isArray!Src || isIntegral!Src) && isArray!Dst){
    if (__ctfe){
        foreach (i; 0 .. length)
            setByte(dst, dstOffset + i, getByte(src, srcOffset + i));
    }else{
        alias length l;
        static if (isArray!Src)
            (cast(ubyte[])dst)[dstOffset .. dstOffset + l] = (cast(ubyte[])src)[srcOffset .. srcOffset + l];
        else
            (cast(ubyte[])dst)[dstOffset .. dstOffset + l] = (cast(ubyte*)&src + srcOffset)[0 .. l];
    }
}

void memSet(A)(ref A a, size_t offset, size_t length, ubyte value) @trusted pure nothrow
    if (isArray!A){
    if (__ctfe){
        foreach (i; 0 .. length)
            setByte(a, offset + i, value);
    }else{
        alias length l;
        (cast(ubyte[])a)[offset .. offset + l] = value;
    }
}

void memSet(A)(ref A a, size_t offset, ubyte value)
    if (isArray!A){
    if (__ctfe){
        alias ElementType!A E;
        memSet(a, offset, a.length * E.sizeof - offset, value);
    }else{
        (cast(ubyte[])a)[offset .. $] = value;
    }
}

public:

/// Base class for all hash functions
class SHA256{
    private uint[] savedIV = null;
    protected static const blockLen = 16 * uint.sizeof;
    protected uint[8] h;
    protected uint[64] w;
    protected size_t offset;
    
    protected void setIV() @safe nothrow{
        h[0] = 0x6a09e667;
        h[1] = 0xbb67ae85;
        h[2] = 0x3c6ef372;
        h[3] = 0xa54ff53a;
        h[4] = 0x510e527f;
        h[5] = 0x9b05688c;
        h[6] = 0x1f83d9ab;
        h[7] = 0x5be0cd19;
    }

    protected ulong bits;
    /**
    All hash functions support byte (octet) hashing, but not all of them support messages
    that have length expressed in bits. This property return true if bit hashing is supported.
    */
    
    this(){
        reset();
    }

    /**
    Hash function update operation. This also forms an OutputRange.
    Params: data = Data to append to the hash buffer. May be an input range.
    */
    final void put(T)(in T data){
        static if (isArray!T)
            putArray(cast(ubyte[])data);
        else static if (isInputRange!T){
            foreach (e; data)
                put(e);
        }else
            putArray((cast(ubyte*)&data)[0 .. T.sizeof]);
    }
    
    /**
    Finalizes hash computation and returns computed hash.
    
    Hash buffer is filled up to its length, so this may be used to get truncated hashes. If hash
    buffer is not specified then full hash is returned.
    
    Params:
    hash = Optional hash buffer. If it is null the buffer is created internally. However, it is
    recommended to create that buffer manually to avoid unnecessary array allocations, especially
    when computing many hashes.
    
    lastBits = If hash function support per bit hashing this specifies how many bits
    was in the last appended byte.
    
    Returns: Computed hash as ubyte array.
    */
    final ubyte[] finish(ubyte[] hash = null){
        
        if (!hash)
            hash = new ubyte[hashLength];

        finishInternal(hash);
        return hash;
    }

    /**
    Finalizes hash computation and returns computed hash as hex string.
    
    Params:
    lowerCase = true if hex string must be in lower case, false if in upper case
    lastBits = If hash function support per bit hashing this specifies how many bits
    was in the last appended byte.
    
    Returns: Computed hash as hex string.
    */
    final string finishToHex(bool lowerCase = true){
        ubyte[] hash = finish(null);
        char[] hex = new char[hashLength * 2];
        
        foreach (i, b; hash){
            hex[i * 2] = hexDigits[b >> 4];
            hex[i * 2 + 1] = hexDigits[b & 0x0F];
        }
        
        if (lowerCase)
            hex = toLower(hex);
        
        return cast(string)hex;
    }
    
    protected void finishInternal(ubyte[] hash){
        setByte(w, offset++, cast(ubyte)0x80); // append one bit
        padTo(56);
        
        bits = swapEndian(bits);
        
        memCopy(w, 56, bits, 0, 8);
        transform();
        
        foreach(ref a; h)
            a = swapEndian(a);
        
        memCopy(hash, 0, h, 0, min(32, hash.length));
    }

    protected void transform() @safe nothrow pure{
        foreach (i; 0 .. 16)
            w[i] = swapEndian(w[i]);
        
        uint a, b, c, d, e, f, g, h;
        uint s0, s1, ch, maj, t1, t2;

        foreach (i; 16 .. 64){
            s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        
        a = this.h[0];
        b = this.h[1];
        c = this.h[2];
        d = this.h[3];
        e = this.h[4];
        f = this.h[5];
        g = this.h[6];
        h = this.h[7];
        
        foreach (i; 0 .. 64){
            s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            ch = (e & f) ^ (~e & g);
            maj = (a & b) ^ (a & c) ^ (b & c);
            t1 = h + s1 + ch + k256[i] + w[i];
            t2 = s0 + maj;
            
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        
        this.h[0] += a;
        this.h[1] += b;
        this.h[2] += c;
        this.h[3] += d;
        this.h[4] += e;
        this.h[5] += f;
        this.h[6] += g;
        this.h[7] += h;
    }



    final @property size_t blockLength() @safe pure nothrow const{
        return blockLen;
    }
    
    final @property size_t hashLength() @safe pure nothrow const{
        return 32;
    }

    final void reset() @safe nothrow{
        if (savedIV)
            h[] = savedIV;
        else
            setIV();
        offset = 0;
        bits = 0;
    }

    final void saveIV(){
        if (!savedIV)
            savedIV = new uint[8];
        savedIV[] = h;
    }
    
    final void restoreOriginalIV(){
        savedIV = null;
    }
    
    final protected void padTo(in size_t bytes, in ubyte pad = 0) @trusted nothrow{
        assert(bytes < blockLength);
        
        if (offset > bytes){
            // we need additional block
            memSet(w, offset, pad);
            transform();
            memSet(w, 0, bytes, pad);
        }else{
            memSet(w, offset, bytes - offset, pad);
        }
        
        offset = bytes;
    }

    final void putArray(const(ubyte)[] data) @trusted nothrow{
        bits += data.length << 3;
        size_t remaining = blockLength - offset;

        if (data.length >= remaining){
            memCopy(w, offset, data, 0, remaining);

            transform();
            data = data[remaining .. $];
            
            if (data.length >= blockLength){
                size_t blockCount = data.length / blockLength;

                foreach (i; 0 .. blockCount){
                    memCopy(w, 0, data, i * blockLength, blockLength);
                    transform();
                }
                
                data = data[blockCount * blockLength .. $];
            }
            
            offset = 0;
        }
        
        if (data.length){
            memCopy(w, offset, data, 0, data.length);
            offset += data.length;
        }
    }
}

///
    /**
    Shorthand function to hash data
    Params:
    data = Data to hash
    Returns: Computed hash as ubyte array.
    Example:
    ---
    ubyte[] digest = hash!SHA1("The quick brown fox jumps over the lazy dog");
    assert(digest.length == 20);
    ---
    */
    auto hash(T)(in T data){
        auto h = new SHA256;
        h.put(data);
        return h.finish();
    }

    /**
    Shorthand function to hash data

    Params:
    data = Data to hash
    lowerCase = true if hex string must be in lower case, false if in upper case
    Returns: Computed hash as hex string.
    Example:
    ---
    string digest = hashToHex!SHA1("The quick brown fox jumps over the lazy dog");
    assert(digest == "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12");
    ---
    */
public:
    auto hex256(T)(in T data, bool lowerCase = true){
        auto h = new SHA256;
        h.put(data);
        return h.finishToHex(lowerCase);
    }