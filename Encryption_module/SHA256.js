class SHA256 {

    /**
     * Array of round constants:
     * (first 32 bits of the fractional parts of the cube roots of the first 64 primes 2...311)
     * 
     * @param {number[]} K - array of round constants
     * 
     * @privete
     */
    static K = [0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
                0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
                0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
                0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
                0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
                0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
                0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
                0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2]

    
    /**
     * Initialize hash values:
     * (first 32 bits of the fractional parts of the square roots of the first 8 primes 2...19):
     * 
     * @param {number[]} H - Array of hash values
     * 
     * @privete
     */
    static H = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
    
    /**
     * Generates SHA-256 hash of string.
     *
     * @param   {string} msg - (Unicode) string to be hashed.
     * @returns {string} Hash of msg as hex character string.
     *
     * @example
     *   import Sha256 from './sha256.js';
     *   const hash = Sha256.hash('abc'); // 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
     */
    static encrypt(message) {
        //convert string to UTF-8, as SHA only deals with byte-streams
        let m = new TextEncoder().encode(message, 'utf-8').reduce((prev, curr) => prev + String.fromCharCode(curr), '');

        let H = [...this.H];
        let K = [...this.K];

        // add trailing '1' bit (+ 0's padding) to string
        m += String.fromCharCode(0x80);
        
        // convert string msg into 512-bit blocks (array of 16 32-bit integers)
        const l = m.length/4 + 2; // length (in 32-bit integers) of msg + ‘1’ + appended length
        const N = Math.ceil(l/16);  // number of 16-integer (512-bit) blocks required to hold 'l' ints
        const mArr = new Array(N);     // message mArr is N×16 array of 32-bit integers

        for (let i=0; i<N; i++) {
            mArr[i] = new Array(16);
            for (let j=0; j<16; j++) { // encode 4 chars per integer (64 per block), big-endian encoding
                mArr[i][j] = (m.charCodeAt(i*64+j*4+0)<<24) | (m.charCodeAt(i*64+j*4+1)<<16)
                        | (m.charCodeAt(i*64+j*4+2)<< 8) | (m.charCodeAt(i*64+j*4+3)<< 0);
            } // note running off the end of msg is ok 'cos bitwise ops on NaN return 0
        }

        // add length (in bits) into final pair of 32-bit integers (big-endian)
        // note: most significant word would be (len-1)*8 >>> 32, but since JS converts
        // bitwise-op args to 32 bits, we need to simulate this by arithmetic operators
        const lenHi = ((m.length-1)*8) / Math.pow(2, 32);
        const lenLo = ((m.length-1)*8) >>> 0;
        mArr[N-1][14] = Math.floor(lenHi);
        mArr[N-1][15] = lenLo;

        //Process the message in successive 512-bit chunks:
        for (let i=0; i<N; i++) {
            const W = new Array(64);

            //(The initial values in w[0..63] don't matter, so many implementations zero them here)
            for (let t=0;  t<16; t++) W[t] = mArr[i][t];

            //Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
            for (let t=16; t<64; t++) {
                W[t] = (SHA256.σ1(W[t-2]) + W[t-7] + SHA256.σ0(W[t-15]) + W[t-16]) >>> 0;
            }

            //Initialize working variables to current hash value:
            let a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];

            //Compression function main loop:
            for (let t=0; t<64; t++) {
                const T1 = h + SHA256.Σ1(e) + SHA256.Ch(e, f, g) + K[t] + W[t];
                const T2 =     SHA256.Σ0(a) + SHA256.Maj(a, b, c);
                h = g;
                g = f;
                f = e;
                e = (d + T1) >>> 0;
                d = c;
                c = b;
                b = a;
                a = (T1 + T2) >>> 0;
            }

            //Add the compressed chunk to the current hash value:
            H[0] = (H[0]+a) >>> 0;
            H[1] = (H[1]+b) >>> 0;
            H[2] = (H[2]+c) >>> 0;
            H[3] = (H[3]+d) >>> 0;
            H[4] = (H[4]+e) >>> 0;
            H[5] = (H[5]+f) >>> 0;
            H[6] = (H[6]+g) >>> 0;
            H[7] = (H[7]+h) >>> 0;
        }

        for (let h=0; h<H.length; h++) H[h] = ('00000000'+H[h].toString(16)).slice(-8);

        const separator = '';

        return H.join(separator);
    }

    /**
     * Rotates right (circular right shift) value x by n positions
     * 
     * @param {number} n 
     * @param {number} x 
     * @returns {number}
     * 
     * @private
     */
    static _ROTR = (n, x) => (x >>> n) | (x << (32-n));

    /**
     * 
     * Logical function.
     * @private
     */
    static σ0 = x => SHA256._ROTR(7,  x) ^ SHA256._ROTR(18, x) ^ (x>>>3);
    /**
     * 
     * Logical function.
     * @private
    */
    static σ1 = x => SHA256._ROTR(17, x) ^ SHA256._ROTR(19, x) ^ (x>>>10);
    /**
     * 
     * Logical function.
     * @private
     */
    static Σ0 = x => SHA256._ROTR(2,  x) ^ SHA256._ROTR(13, x) ^ SHA256._ROTR(22, x);
    /**
     * 
     * Logical function.
     * @private
     */
    static Σ1 = x => SHA256._ROTR(6,  x) ^ SHA256._ROTR(11, x) ^ SHA256._ROTR(25, x);
    /**
     * 
     * Logical function.
     * @private
     */
    static Ch = (x, y, z) =>  (x & y) ^ (~x & z);
    /**
     * 
     * Logical function.
     * @private
     */
    static Maj = (x, y, z) => (x & y) ^ (x & z) ^ (y & z);
}

module.exports = SHA256;