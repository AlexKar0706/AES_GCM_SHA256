const SHA256 = require('./SHA256');
const AES = require('./AES');

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

class AES_GCM_SHA256 extends AES {

    /**
     * Encrypt a text using AES encryption in Counter mode of operation.
     *
     * Unicode multi-byte character safe.
     *
     * @param   {string} plaintext - Source text to be encrypted.
     * @param   {string} password - The password to use to generate a key for encryption.
     * @param   {number | 128} nBits - Number of bits (Default 128) to be used in the key; 128 / 192 / 256.
     * @param   {string} authData - Authentication data of sender
     * @returns {string} Encrypted text, base-64 encoded.
     *
     * @example
     *   const encr = AES_GCM_SHA256.encrypt('big secret', 'pāşšŵōřđ', 'ip:192.168.1.1', 128); // 'TwI6amwIcmAClp64l52n4KlTYAeTMVfNTCKDj9NMBRgEBA=='
     */
    static encrypt(plaintext, password, authData, nBits = 128) {
        if (![ 128, 192, 256 ].includes(nBits)) throw new Error('Key size is not 128 / 192 / 256');
        plaintext = AES_GCM_SHA256.utf8Encode(String(plaintext));
        password = AES_GCM_SHA256.utf8Encode(String(password));
        authData = AES_GCM_SHA256.utf8Encode(String(authData));

        //use SHA256 Hash function to encrypt and expand password to 32 bytes long
        let key = SHA256.encrypt(password); // create 32-byte key
        key = key.slice(0, nBits/8); // set fixed 16/24/32 byte key

        // initialise 1st 8 bytes of counter block with nonce (NIST SP 800-38A §B.2): [0-1] = millisec,
        // [2-3] = random, [4-7] = seconds, together giving full sub-millisec uniqueness up to Feb 2106
        const timestamp = (new Date()).getTime(); // milliseconds since 1-Jan-1970
        const nonceMs = timestamp%1000;
        const nonceSec = Math.floor(timestamp/1000);
        const nonceRnd = Math.floor(Math.random()*0xffff);
        // for debugging: const [ nonceMs, nonceSec, nonceRnd ] = [ 0, 0, 0 ];
        const counterBlock = [ // 16-byte array; blocksize is fixed at 16 for AES
            nonceMs  & 0xff, nonceMs >>>8 & 0xff,
            nonceRnd & 0xff, nonceRnd>>>8 & 0xff,
            nonceSec & 0xff, nonceSec>>>8 & 0xff, nonceSec>>>16 & 0xff, nonceSec>>>24 & 0xff,
            0, 0, 0, 0, 0, 0, 0, 0,
        ];

        // and convert nonce to a string to go on the front of the ciphertext
        const nonceStr = counterBlock.slice(0, 8).map(i => String.fromCharCode(i)).join('');

        // convert (utf-8) plaintext to byte array
        const plaintextBytes = plaintext.split('').map(ch => ch.charCodeAt(0));

        // convert (utf-8) authentication data to byte array
        const authDataBytes = authData.split('').map(ch => ch.charCodeAt(0));

        // ------------ perform encryption ------------
        const [ciphertextBytes, cipherTagBytes] = AES_GCM_SHA256.GCM_Encryption(plaintextBytes, key, counterBlock, authDataBytes);

        // convert byte array to (utf-8) ciphertext string
        const ciphertextUtf8 = ciphertextBytes.map(i => String.fromCharCode(i)).join('');

        // convert tag byte array to (utf-8) tag string
        const cipherTagUtf8 = cipherTagBytes.map(i => String.fromCharCode(i)).join('');

        // base-64 encode ciphertext
        const ciphertextB64 =  AES_GCM_SHA256.base64Encode(nonceStr + ciphertextUtf8 + cipherTagUtf8);

        return ciphertextB64;
    }

    /**
     *  Galois/Counter Mode (GCM) is a mode of operation for symmetric-key cryptographic block ciphers which is widely adopted for its performance.
     *  - All operation are done in GF(2^128) field. 
     *  - 0^128 - means a string of 128 bits
     * 
     *  Steps:
     *  1. Get H hash key using encryption algorithm H = AES(0^128, K)
     *  2. Get Special Y, which is actually a counter block for CTR mode.
     *      1. if length of IV is 96 bit, add 0^31 and last 1 bit to IV to creat Y0
     *      2. if length of IV is not 96 bit, use GHASH function to create Y0 = GHASH(H, {}, IV ).
     *  3. Encrypt first block Y0 using encryption algorithm, and save it for futher
     *  4. Encrypt plainttext using encrypted blocks Y(1 + n) and counter mode method, where n - one 16 byte block
     *      1. Ci = Pi ⊕ E(K, Yi) for i = 1, . . . , n − 1
     *  5. Create Tag of encryption using GHASH function and concatenated byte string of authentication data, encrypted text and their length
     *      1. T = GHASH(H, A, C, len(A), len(C)) ⊕ E(K, Y0)
     *
     * 
     * @param   {number[]} plaintext - Plaintext to be encrypted, as byte array.
     * @param   {number[]} key - Key to be used to encrypt plaintext.
     * @param   {number[]} IV - Initial 16-byte vector (with nonce & 0 counter).
     * @param   {number[]} A - Authentication data of sender
     * @returns {[number[], number[]]} Ciphertext and Crypted Tag as byte array.
     *
     * @private
     */
    static GCM_Encryption(plaintext, key, IV, A) {

        // It is considered that each element of the array contains 1 byte or 8 bits.
        const bits = 8;
          
        // generate key schedule - an expansion of the key into distinct Key Rounds for each round
        const keySchedule = AES.keyExpansion(key);

        //Step 1
        const zeroBlock = new Array(16)
        for (let i = 0; i < zeroBlock.length; i++) {
            zeroBlock[i] = 0;
        }
        const H = AES.cipher(zeroBlock, keySchedule); // Combine key with 0^128 block of bits

        //Step 2
        let Y, additionalBlock;
        if (IV.length * bits === 96) { //If len(IV) is 96 bits, we can avoid using GHASH function
            additionalBlock = [0, 0, 0, 1]
            Y = IV.concat(additionalBlock);
        } else { //If len(IV) is not 96 bits, we have to use GHASH function

            //This step is needed to expand IV to block, which is devided by 128 for GHASH function
            let s = 128 * (Math.ceil(IV.length * bits / 128)) - IV.length * bits
            additionalBlock = new Array(8+(s/8))
            for (let i = 0; i < additionalBlock.length; i++) {
                additionalBlock[i] = 0;
            }

            let IVBlock64BitLength = AES_GCM_SHA256.create64BitBlockLength(IV);
            
            Y = AES_GCM_SHA256.GHASH(IV.concat(additionalBlock, IVBlock64BitLength), H);
        }

        //Step 3 & Step 4
        const [Y0, ciphertext] = AES_GCM_SHA256.counterMode_encrypt(plaintext, key, Y);

        //Step 5
        //This step is needed to expand Authentication data and ciphertext to block, which is devided by 128 for GHASH function
        let u = 128*(Math.ceil(ciphertext.length*bits/128)) - ciphertext.length*bits
        let v = 128*(Math.ceil(A.length*bits/128)) - A.length*bits

        const zeroBlock_u = new Array(u/8)
        for (let i = 0; i < zeroBlock_u.length; i++) {
            zeroBlock_u[i] = 0;
        }

        const zeroBlock_v = new Array(v/8)
        for (let i = 0; i < zeroBlock_v.length; i++) {
            zeroBlock_v[i] = 0;
        }

        const ABlock64BitLength = AES_GCM_SHA256.create64BitBlockLength(A);
        const CBlock64BitLength = AES_GCM_SHA256.create64BitBlockLength(ciphertext);

        const S = AES_GCM_SHA256.GHASH(A.concat(zeroBlock_v, ciphertext, zeroBlock_u, ABlock64BitLength, CBlock64BitLength), H);

        const Tag = AES_GCM_SHA256.GF_add(S, Y0);

        return [ciphertext, Tag]
    }

    /**
     * NIST SP 800-38A sets out recommendations for block cipher modes of operation in terms of byte
     * operations. This implements the §6.5 Counter Mode (CTR).
     *
     *     Oⱼ = CIPHₖ(Tⱼ)      for j = 1, 2 … n
     *     Cⱼ = Pⱼ ⊕ Oⱼ        for j = 1, 2 … n-1
     *     C*ₙ = P* ⊕ MSBᵤ(Oₙ) final (partial?) block
     *   where CIPHₖ is the forward cipher function, O output blocks, P plaintext blocks, C
     *   ciphertext blocks
     *
     * @param   {number[]} plaintext - Plaintext to be encrypted, as byte array.
     * @param   {number[]} key - Key to be used to encrypt plaintext.
     * @param   {number[]} counterBlock - Initial 16-byte CTR counter block (with nonce & 0 counter).
     * @returns {[number[], number[]]} Y0 and Ciphertext as byte array.
     *
     * @private
     */
    static counterMode_encrypt(plaintext, key, counterBlock) {
        const blockSize = 16; // block size fixed at 16 bytes / 128 bits (Nb=4) for AES

        // generate key schedule - an expansion of the key into distinct Key Rounds for each round
        const keySchedule = AES.keyExpansion(key);

        const blockCount = Math.ceil(plaintext.length/blockSize);
        const ciphertext = new Array(plaintext.length);

        //Create first special block Y0 for encryption of Tag
        const Y0 = AES.cipher(counterBlock, keySchedule);

        // increment counter block (counter in 2nd 8 bytes of counter block, big-endian)
        counterBlock[blockSize-1]++;

        // and propagate carry digits
        for (let i=blockSize-1; i>=8; i--) {
            counterBlock[i-1] += counterBlock[i] >> 8;
            counterBlock[i] &= 0xff;
        }

        for (let b=0; b<blockCount; b++) {
            // ---- encrypt counter block; Oⱼ = CIPHₖ(Tⱼ) ----
            const cipherCntr = AES.cipher(counterBlock, keySchedule);
            // block size is reduced on final block
            const blockLength = b<blockCount-1 ? blockSize : (plaintext.length-1)%blockSize + 1;

            // ---- xor plaintext with ciphered counter byte-by-byte; Cⱼ = Pⱼ ⊕ Oⱼ ----
            for (let i=0; i<blockLength; i++) {
                ciphertext[b*blockSize + i] = cipherCntr[i] ^ plaintext[b*blockSize + i];
            }

            // increment counter block (counter in 2nd 8 bytes of counter block, big-endian)
            counterBlock[blockSize-1]++;

            // and propagate carry digits
            for (let i=blockSize-1; i>=8; i--) {
                counterBlock[i-1] += counterBlock[i] >> 8;
                counterBlock[i] &= 0xff;
            }

        }

        return [Y0, ciphertext]
    }

    /**
     * Decrypt a text encrypted by AES in counter mode of operation.
     *
     * @param   {string} ciphertext - Cipher text to be decrypted.
     * @param   {string} password - Password to use to generate a key for decryption.
     * @param   {number | 128} nBits - Number of bits (Default 128) to be used in the key; 128 / 192 / 256.
     * @param   {string} authData - Authentication data of sender
     * @returns {string} Decrypted text
     *
     * @example
     *   const decr = AES_GCM_SHA256.decrypt('TwI6amwIcmAClp64l52n4KlTYAeTMVfNTCKDj9NMBRgEBA==', 'pāşšŵōřđ', 'ip:192.168.1.1', 128); // 'big secret'
     */
    static decrypt(ciphertext, password, authData, nBits = 128) {
        if (![ 128, 192, 256 ].includes(nBits)) throw new Error('Key size is not 128 / 192 / 256');
        ciphertext = AES_GCM_SHA256.base64Decode(String(ciphertext));
        password = AES_GCM_SHA256.utf8Encode(String(password));
        authData = AES_GCM_SHA256.utf8Encode(String(authData));

        //use SHA256 Hash function to encrypt and expand password to 32 bytes long
        let key = SHA256.encrypt(password); // create 32-byte key
        key = key.slice(0, nBits/8); // set fixed 16/24/32 byte key

        // recover nonce from 1st 8 bytes of ciphertext into 1st 8 bytes of counter block

        const counterBlock = [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ];
        for (let i=0; i<8; i++) counterBlock[i] = ciphertext.charCodeAt(i);

        // recover crypted Tag from last 16 bytes of ciphertext
        const cipherTagBytes = new Array(16);
        for (let i=0; i < 16; i++) cipherTagBytes[i] = ciphertext.charCodeAt(ciphertext.length - i - 1);
        cipherTagBytes.reverse()

        // convert ciphertext to byte array (skipping past initial 8 bytes)
        const ciphertextBytes = new Array(ciphertext.length-24);
        for (let i=8; i<ciphertextBytes.length + 8; i++) ciphertextBytes[i-8] = ciphertext.charCodeAt(i);

        //Convert authentication data of sender to byte array (skipping past initial 8 bytes)
        const authDataBytes = authData.split('').map(ch => ch.charCodeAt(0));

        // ------------ perform decryption ------------
        const plaintextBytes = AES_GCM_SHA256.GCM_decryption(ciphertextBytes, key, counterBlock, cipherTagBytes, authDataBytes);

        // convert byte array to (utf-8) plaintext string
        const plaintextUtf8 = plaintextBytes.map(i => String.fromCharCode(i)).join('');

        // decode from UTF8 back to Unicode multi-byte chars
        const plaintext = AES_GCM_SHA256.utf8Decode(plaintextUtf8);

        return plaintext;
    }

    /**
     *  Galois/Counter Mode (GCM) is a mode of operation for symmetric-key cryptographic block ciphers which is widely adopted for its performance.
     *  - All operation are done in GF(2^128) field. 
     *  - 0^128 - means a string of 128 bits
     * 
     *  Steps:
     *  1. Get H hash key using encryption algorithm H = AES(0^128, K)
     *  2. Get Special Y, which is actually a counter block for CTR mode.
     *      1. if length of IV is 96 bit, add 0^31 and last 1 bit to IV to creat Y0
     *      2. if length of IV is not 96 bit, use GHASH function to create Y0 = GHASH(H, {}, IV ).
     *  3. Decrypt first block Y0 using decryption algorithm, and save it for the futher
     *  4. Decrypt plainttext using decrypted blocks Y(1 + n) and counter mode method, where n - one 16 byte block
     *      1. Pi = Ci ⊕ E(K, Yi) for i = 1, . . . , n − 1
     *  5. Create Tag of encryption using GHASH function and concatenated byte string of authentication data, ciphertext and their length
     *      1. T = GHASH(H, A, C, len(A), len(C)) ⊕ E(K, Y0)
     *  6. Compare Encrypted Tag of sender with the new encrypted Tag
     *      1. If they are equal, return plainttext
     *      2. If they are not equal, throw Error  
     *
     * 
     * @param   {number[]} plaintext - Plaintext to be encrypted, as byte array.
     * @param   {number[]} key - Key to be used to encrypt plaintext.
     * @param   {number[]} IV - Initial 16-byte vector (with nonce & 0 counter).
     * @param   {number[]} A - Authentication data of sender
     * @returns {[number[], number[]]} Ciphertext and Crypted Tag as byte array.
     *
     * @private
     */
    static GCM_decryption(ciphertext, key, IV, senderCryptTag, A) {
        // It is considered that each element of the array contains 1 byte or 8 bits.
        const bits = 8;

        // generate key schedule - an expansion of the key into distinct Key Rounds for each round
        const keySchedule = AES.keyExpansion(key);

        //Step 1
        const zeroBlock = new Array(16)
        for (let i = 0; i < zeroBlock.length; i++) {
            zeroBlock[i] = 0;
        }
        const H = AES.cipher(zeroBlock, keySchedule); // Combine key with 0^128 block of bits

        //Step 2
        let Y, additionalBlock;
        if (IV.length * bits === 96) { //If len(IV) is 96 bits, we can avoid using GHASH function
            additionalBlock = [0, 0, 0, 1]
            Y = IV.concat(additionalBlock);
        } else { //If len(IV) is not 96 bits, we have to use GHASH function

            //This step is needed to expand IV to block, which is devided by 128 for GHASH function
            let s = 128 * (Math.ceil(IV.length * bits / 128)) - IV.length * bits
            additionalBlock = new Array(8+(s/8))
            for (let i = 0; i < additionalBlock.length; i++) {
                additionalBlock[i] = 0;
            }

            let IVBlock64BitLength = AES_GCM_SHA256.create64BitBlockLength(IV);
            
            Y = AES_GCM_SHA256.GHASH(IV.concat(additionalBlock, IVBlock64BitLength), H);
        }

        //Step 3 & Step 4
        const [plaintext, Y0] = AES_GCM_SHA256.counterMode_decrypt(ciphertext, key, Y);
        
        //Step 5
        //This step is needed to expand Authentication data and ciphertext to block, which is devided by 128 for GHASH function
        let u = 128*(Math.ceil(ciphertext.length*bits/128)) - ciphertext.length*bits
        let v = 128*(Math.ceil(A.length*bits/128)) - A.length*bits

        const zeroBlock_u = new Array(u/8)
        for (let i = 0; i < zeroBlock_u.length; i++) {
            zeroBlock_u[i] = 0;
        }

        const zeroBlock_v = new Array(v/8)
        for (let i = 0; i < zeroBlock_v.length; i++) {
            zeroBlock_v[i] = 0;
        }

        const ABlock64BitLength = AES_GCM_SHA256.create64BitBlockLength(A);
        const CBlock64BitLength = AES_GCM_SHA256.create64BitBlockLength(ciphertext);

        const S = AES_GCM_SHA256.GHASH(A.concat(zeroBlock_v, ciphertext, zeroBlock_u, ABlock64BitLength, CBlock64BitLength), H);

        const Tag = AES_GCM_SHA256.GF_add(S, Y0);
        
        //Step 6
        for (let i = 0; i < senderCryptTag.length; i++) {
            if (senderCryptTag[i] !== Tag[i]) throw new Error("Crypted Tag of sender was corrupted");
        }

        return plaintext
    }

    /**
     * NIST SP 800-38A sets out recommendations for block cipher modes of operation in terms of byte
     * operations. This implements the §6.5 Counter Mode (CTR).
     *
     *     Oⱼ = CIPHₖ(Tⱼ)      for j = 1, 2 … n
     *     Pⱼ = Cⱼ ⊕ Oⱼ        for j = 1, 2 … n-1
     *     P*ₙ = C* ⊕ MSBᵤ(Oₙ) final (partial?) block
     *   where CIPHₖ is the forward cipher function, O output blocks, C ciphertext blocks, P
     *   plaintext blocks
     *
     * @param   {number[]} ciphertext - Ciphertext to be decrypted, as byte array.
     * @param   {number[]} key - Key to be used to decrypt ciphertext.
     * @param   {number[]} counterBlock - Initial 16-byte CTR counter block (with nonce & 0 counter).
     * @returns {number[]} Plaintext as byte array.
     *
     * @private
     */
    static counterMode_decrypt(ciphertext, key, counterBlock) {
        const blockSize = 16; // block size fixed at 16 bytes / 128 bits (Nb=4) for AES

        // generate key schedule - an expansion of the key into distinct Key Rounds for each round
        const keySchedule = AES.keyExpansion(key);

        const blockCount = Math.ceil(ciphertext.length/blockSize);
        const plaintext = new Array(ciphertext.length);

        //Create first special block Y0 for encryption of Tag
        const Y0 = AES.cipher(counterBlock, keySchedule);
        // increment counter block (counter in 2nd 8 bytes of counter block, big-endian)
        counterBlock[blockSize-1]++;
        // and propagate carry digits
        for (let i=blockSize-1; i>=8; i--) {
            counterBlock[i-1] += counterBlock[i] >> 8;
            counterBlock[i] &= 0xff;
        }

        for (let b=0; b<blockCount; b++) {
            // ---- decrypt counter block; Oⱼ = CIPHₖ(Tⱼ) ----
            const cipherCntr = AES.cipher(counterBlock, keySchedule);

            // block size is reduced on final block
            const blockLength = b<blockCount-1 ? blockSize : (ciphertext.length-1)%blockSize + 1;

            // ---- xor ciphertext with ciphered counter byte-by-byte; Pⱼ = Cⱼ ⊕ Oⱼ ----
            for (let i=0; i<blockLength; i++) {
                plaintext[b*blockSize + i] = cipherCntr[i] ^ ciphertext[b*blockSize + i];
            }

            // increment counter block (counter in 2nd 8 bytes of counter block, big-endian)
            counterBlock[blockSize-1]++;
            // and propagate carry digits
            for (let i=blockSize-1; i>=8; i--) {
                counterBlock[i-1] += counterBlock[i] >> 8;
                counterBlock[i] &= 0xff;
            }

        }

        return [plaintext, Y0];
    }

    /* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

    /**
     * The GHASH algorithm is a special form of the
        Carter-Wegman polynomial evaluation MAC. Each 16-bytes block of the
        authenticated data is multiplied by a different power of the hash key (H), where
        computations occur in some specific binary finite field that we denote here by
        GF_GCM(2^128)
     * 
     * 
     * @param {number[]} DATA - Byte array, which containes data to hash (the bit length of DATA is assumed to be divisible by 128) 
     * @param {number[]} H - hash key of GCM algorithm
     * @returns {number[]} Hashed 128 byte-array of DATA byte-array
     * 
     * @private
     */
    static GHASH(DATA, H) {
        //The number of bits in one byte array element
        const bits = 8;

        //Devide long DATA byte array to 16-byte blocks
        const N = DATA.length * bits / 128
        const M = new Array(N)

        for (let i = 0; i < N; i++) {
            M[i] = DATA.slice(i*16, i*16 + 16)
        }

        //Calculate hash function using formula: M(1)×H + M(2)×H + … + M(N)×H
        let ans = AES_GCM_SHA256.GF_mul(M[0], H)
        for (let i = 1; i < N; i++) {
            ans = AES_GCM_SHA256.GF_add(ans, AES_GCM_SHA256.GF_mul(M[i], H))
        }
        return ans
    }


    /**
     * Addition operation in GF_GCM(2^128)
     * 
     * 
     * @param {number[]} arr1 //First byte-array
     * @param {number[]} arr2 //Second byte-array
     * @returns {number[]} Product of addition
     * 
     * @private
     */
    static GF_add (arr1, arr2) {
        const X = [...arr1];
        const Y = [...arr2];
        for (let i = 0; i < X.lenght; i++) {
            X[i] ^= Y[i]
        }
        return X
    }

    /**
     * Multiplication operation in GF_GCM(2^128)
     * 
     * 
     * 
     * @param {number[]} arr1 //First byte-array
     * @param {number[]} arr2 //Second byte-array
     * @returns {number[]} Product of multiplication
     * 
     * @private
     */

    static GF_mul (arr1, arr2) {
        let X = [...arr1]
        const Y = [...arr2]
        const Z = new Array(16); // Product of two byte-arrays multiplications

        for (let i = 0; i < Z.length; i++) {
            Z[i] = 0;
        }

        const R = new Array(16) // Special polynomial byte-array for multiplication, which is using value R = 11100001||0^120
        R[0] = 225
        for(let i = 1; i < R.length; i++) {
            R[i] = 0;
        }

        for (let i = 0; i < 128; i++) {
            if (Y[parseInt(i/8)] & (1 << (i % 8))) {
                for (let j = 0; j < 16; j++) {
                    Z[j] ^= X[j];
                }
            }

            if((X[15] & 128) === 0) {
                X = AES_GCM_SHA256.Rsh_byte_array(X);
            } else {
                X = AES_GCM_SHA256.Rsh_byte_array(X);
                for (let j = 0; j < 16; j++) {
                    X[j] ^= R[j];
                } 
            }
        }
        return Z
    }

    /**
     * Special Right Shift function, this implimintation is using byte-array
     * 
     * @param {number[]} A - Byte-array
     * @returns {number[]} Rightshifted byte-array
     * 
     * @private
    */
    static Rsh_byte_array (A) {
        const X = [...A];
        for (let i = 0, prev_carry = 0, curr_carry = 0; i < X.length; i++) {
            if (X[i] & 1) curr_carry = 1;
            X[i] >>= 1;
            
            if (prev_carry) {
                X[i] += 128;
                prev_carry = 0
            }

            if (curr_carry) {
                prev_carry = 1;
                curr_carry = 0;
            }

        }
        return X
    }
    /**
     * Special function to create 64 bit byte-array, which is containes length of the original byte-array
     * 
     * @param {number[]} A - Initial byte-array
     * @returns {number[]} The block of 64 bits, which is contains A element length
     * 
     * @private
     */
    static create64BitBlockLength(A) {
        let Block64BitLength = new Array(8);
        Block64BitLength = [0, 0, 0, 0, 0, 0, 0, A.length * 8]
        for (let i = 7; i > 0;) {
            if (Block64BitLength[i] === 0) break;

            while (Block64BitLength[i] > 256) {
                Block64BitLength[i] -= 256;
                Block64BitLength[i-1]++;
            }

            i--;
        }
        return Block64BitLength
    }

    /**
     * Encodes multi-byte string to utf8.
     *
     * Note utf8Encode is an identity function with 7-bit ascii strings, but not with 8-bit strings;
     * utf8Encode('x') = 'x', but utf8Encode('ça') = 'Ã§a', and utf8Encode('Ã§a') = 'ÃÂ§a'.
     * 
     * @private
     */
    static utf8Encode(str) {
        try {
            return new TextEncoder().encode(str, 'utf-8').reduce((prev, curr) => prev + String.fromCharCode(curr), '');
        } catch (e) { // no TextEncoder available?
            return unescape(encodeURIComponent(str)); // monsur.hossa.in/2012/07/20/utf-8-in-javascript.html
        }
    }

    /**
     * Decodes utf8 string to multi-byte.
     * 
     * @private
     */
    static utf8Decode(str) {
        try {
            return new TextEncoder().decode(str, 'utf-8').reduce((prev, curr) => prev + String.fromCharCode(curr), '');
        } catch (e) { // no TextEncoder available?
            return decodeURIComponent(escape(str)); // monsur.hossa.in/2012/07/20/utf-8-in-javascript.html
        }
    }

    /**
     * Encodes string as base-64.
     *
     * - developer.mozilla.org/en-US/docs/Web/API/window.btoa, nodejs.org/api/buffer.html
     * - note: btoa & Buffer/binary work on single-byte Unicode (C0/C1), so ok for utf8 strings, not for general Unicode...
     * - note: if btoa()/atob() are not available (eg IE9-), try github.com/davidchambers/Base64.js
     * 
     * @private
     */
    static base64Encode(str) {
        if (typeof btoa != 'undefined') return btoa(str); // browser
        if (typeof Buffer != 'undefined') return new Buffer(str, 'binary').toString('base64'); // Node.js
        throw new Error('No Base64 Encode');
    }

    /**
     * Decodes base-64 encoded string.
     * 
     * @private
     */
    static base64Decode(str) {
        if (typeof atob != 'undefined') return atob(str); // browser
        if (typeof Buffer != 'undefined') return new Buffer(str, 'base64').toString('binary'); // Node.js
        throw new Error('No Base64 Decode');
    }

}


/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
module.exports = AES_GCM_SHA256;