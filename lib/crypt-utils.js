/**
 * Implement simple operations to compatibility with AES encryption used in Java framework.
 * @module crypt-utils
 */
"use strict";
const crypto = require('crypto'),
    // utils = require('./utils'),
    moment = require('moment'),
    WRAP_KEY = 'CBFD693E743B1BF88FE14B1D970DAC27',
    DEFAULT_ID_HASH_KEY = 'C56DCF48589364A2',
    AMZ_KEY = 'x-amz-key',
    AMZ_IV = 'x-amz-iv',
    AMZ_CONTENT_LENGTH = 'x-amz-unencrypted-content-length';

/**
 * Unwrap secret values if it looks encrypted. Wrapped values have mod 32 length and hex characters.
 * @param {String} key
 * @returns {String} unwrapped value
 */
function unwrapIfNeeded(key) {
    if (key && key.length % 32 === 0 && /^[0-9A-Fa-f]+$/.test(key)) {
        return unwrapKey(key);
    } else {
        return key;
    }
}

/**
 * Unwrap specified fields in object
 * @param {Object} obj
 * @param  {...String} fields of field names
 * @return {Object} obj
 */
function unwrapFields(obj, ...fields) {
    // eslint-disable-next-line no-prototype-builtins
    fields.filter(field => obj.hasOwnProperty(field)).forEach(field => {
        obj[field] = unwrapIfNeeded(obj[field]);
    });
    return obj;
}

/**
 * Wrap specified fields in object
 * @param {Object} obj
 * @param  {...String} fields of field names
 * @return {Object} obj
 */
function wrapFields(obj, ...fields) {
    // eslint-disable-next-line no-prototype-builtins
    fields.filter(field => obj.hasOwnProperty(field)).forEach(field => {
        obj[field] = wrapKey(obj[field]);
    });
    return obj;
}

/**
 * Check if the string is a wrapped value.
 * @param {string} key
 * @return {boolean} true if the string can be unwrapped.
 */
function isWrapped(key) {
    return key && key.length % 32 === 0 && /^[0-9A-Fa-f]+$/.test(key)
}

/**
 * Unwrap secret values if it looks encrypted. Wrapped values have mod 32 length and hex characters.
 * @param {String} key - value to unwrap
 * @param {String} wrapKey - decryption key
 * @param {Object} params - decryption parameters.
 * @returns {String} unwrapped value
 */
function unwrapExtIfNeeded(key, wrapKey, params) {
    if (isWrapped(key)) {
        return unwrapKeyExt(key, wrapKey, params);
    } else {
        return key;
    }
}

/**
 * Utility function to wrap supplied key as aes-128-ecb. To match Java supplied text is padded with space
 * to mod32 and then encrypted. Different from 'wrapKey' where this can specify its own WRAP_KEY and params
 * @param {String} key - key in utf8 keeping compatibility with Java
 * @param {String} wrapKey - key in Hex
 * @param {Object} params - {algorithm: default aes-128-ebc, keyEncoding: default hex, wrapKeyEncoding: hex,
 *     finalEncoding: hex}
 * @return {String} - resultant string in hex
 */
function wrapKeyExt(key, wrapKey, params) {
    wrapKey = wrapKey || WRAP_KEY;
    let defaultParams = {
        algo: 'aes-128-ecb',
        keyEncoding: 'hex',
        wrapKeyEncoding: 'hex',
        finalEncoding: 'hex',
        autoPadding: false
    };

    params = utils.merge(defaultParams, params || {});

    // For compatibility with Java rawkey and empty init vector
    const keyBuffer = Buffer.from(wrapKey, params.wrapKeyEncoding);
    let cipher = crypto.createCipheriv(params.algo, keyBuffer, '').setAutoPadding(params.autoPadding);
    let textBuffer = key;

    if (!params.autoPadding) {
        textBuffer = padRightToMod(key, 32, ' ');
    }

    const p1 = cipher.update(textBuffer, params.keyEncoding, params.finalEncoding);
    const p2 = cipher.final(params.finalEncoding);

    return p1 + p2;
}

/**
 * Utility function to wrap supplied key as aes-128-ecb. To match Java supplied text is padded with space
 * to mod32 and then encrypted. Different from 'wrapKey' where this can specify its own WRAP_KEY and params
 * @param {String} encrypted - encrypted key in utf8 keeping compatibility with Java
 * @param {String} wrapKey - key in Hex
 * @param {Object} params - {algorithm: default aes-128-ebc, keyEncoding: default hex, wrapKeyEncoding: hex,
 *     finalEncoding: hex}
 * @return {String} - resultant string in hex
 */
function unwrapKeyExt(encrypted, wrapKey, params) {
    wrapKey = wrapKey || WRAP_KEY;
    let defaultParams = {
        algo: 'aes-128-ecb',
        keyEncoding: 'hex',
        wrapKeyEncoding: 'hex',
        finalEncoding: 'hex',
        autoPadding: false
    };
    params = utils.merge(defaultParams, params || {});

    // For compatibility with Java rawkey and empty init vector
    const keyBuffer = Buffer.from(wrapKey, params.wrapKeyEncoding);
    let decipher = crypto.createDecipheriv(params.algo, keyBuffer, '');
    decipher.setAutoPadding(params.autoPadding);
    let decrypted = decipher.update(encrypted, params.keyEncoding, params.finalEncoding);
    decrypted += decipher.final(params.finalEncoding);
    return decrypted.trim();
}

/**
 * wrap key, equivalent to JCEUtils.wrapParameter
 * @param  {String} plainText key to wrap
 * @return {String} wrapped value
 */
function wrapKey(plainText) {
    let key = Buffer.from(WRAP_KEY, 'hex');
    let cipher = crypto.createCipheriv('aes-128-ecb', key, '');
    cipher.setAutoPadding(false);
    /// -- pad text to 32 character
    plainText = padRightToMod(plainText, 32, ' ');
    let cipherText = cipher.update(plainText, 'utf8', 'hex');
    cipherText += cipher.final('hex');
    return cipherText.toUpperCase();
}

/**
 * unwrap key, equivalent to JCEUtils.unwrapParameter
 * @param  {String} encrypted key
 * @return {String} unwrapped value
 */
function unwrapKey(encrypted) {
    let key = Buffer.from(WRAP_KEY, 'hex');
    let decipher = crypto.createDecipheriv('aes-128-ecb', key, '');
    decipher.setAutoPadding(false);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted.trim();
}

/**
 * Pad string to right until hits mod size.
 * @param  {string} text - text to pad
 * @param  {number} mod  - size
 * @param  {string} pad  - character to pad (default space)
 * @return {string} padded string
 */
function padRightToMod(text, mod, pad = ' ') {
    if (mod < 0) {
        return text;
    }
    text = text || '';
    let len = Buffer.from(text, 'utf-8').length;
    let r = text;
    for (let i = len; i % mod > 0; i++) {
        r += pad;
    }
    return r;
}

/**
 * Generate string of specified size
 * @param  {int} len [description]
 * @param  {string} pad - character to pad (default space)
 * @return {string}
 */
function space(len, pad = ' ') {
    if (len <= 0) {
        return '';
    }
    let s = '';
    for (let i = 0; i < len; i++) {
        s = s + pad;
    }
    return s;
}

/**
 * Pad string on the left to size.
 * @param  {String}    text to pad
 * @param  {int}       len desired length
 * @param  {String} pad character
 * @return {String} padded string
 */
function padLeft(text, len, pad = ' ') {
    text = String(text || '');

    if (len <= text.length) {
        return text;
    }
    len = len - text.length;
    return space(len, pad) + text;
}

/**
 * Pad string on the right to size.
 * @param  {String}    text to pad
 * @param  {int}       len desired length
 * @param  {String} pad character
 * @return {String} padded string
 */
function padRight(text, len, pad = ' ') {
    text = String(text || '');

    if (len <= text.length) {
        return text;
    }

    len = len - text.length;
    return text + space(len, pad);
}

/**
 * Pad string on the left and right to size.
 * @param  {String} text to pad
 * @param  {int}    len desired length
 * @param  {String} pad character
 * @return {String} padded string
 */
function padCenter(text, len, pad = ' ') {
    text = String(text || '');

    if (len <= text.length) {
        return text;
    }

    len = len - text.length;
    let left = Math.trunc(len / 2);
    let right = len - left;
    return space(left, pad) + text + space(right, pad);
}

/**
 * AES Encrypt text using specified key, same as JCEUtils.rijndaelEncryptAndHex
 * @param  {String} plainText to encrypt
 * @param  {String} hexKey HEX encoded AES key
 * @param  {Object} params {autoPadding: default false}
 * @returns {String} encrypted string
 */
function encrypt(plainText, hexKey, params) {
    let defaultParams = {
        autoPadding: false,
    };

    params = utils.merge(defaultParams, params || {});
    let key = Buffer.from(hexKey, 'hex');
    let cipher = crypto.createCipheriv('aes-128-ecb', key, '');
    cipher.setAutoPadding(params.autoPadding);

    if (!params.autoPadding) {
        plainText = padRightToMod(plainText, 32, ' ');
    }

    let encrypted = cipher.update(plainText, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted.toUpperCase();
}

/**
 * AES Decrypt text using specified key, same as JCEUtils.rijndaelDecryptFromHex
 * @param  {String} encrypted hex encoded text to decrypt
 * @param  {String} hexKey HEX encoded AES key
 * @return {String} decrypted string
 */
function decrypt(encrypted, hexKey) {
    let key = Buffer.from(hexKey, 'hex');
    let decipher = crypto.createDecipheriv('aes-128-ecb', key, '');
    decipher.setAutoPadding(false);
    let plainText = decipher.update(encrypted, 'hex', 'utf8');
    plainText += decipher.final('utf8');
    return plainText.trim();
}

/**
 * Decrypt AES encoded text and return parsed out object.
 * @param encrypted
 * @param hexKey
 * @param sep
 * @returns {*}
 */
function decryptToMap(encrypted, hexKey, sep = ';') {
    if (!encrypted) {
        return null;
    }
    const decryptedText = decrypt(encrypted, hexKey);
    if (!decryptedText) {
        return null;
    }
    // Validate that decrypted text is not garbage
    if (!/^[ -~]+$/.test(decryptedText)) {
        // non printable characters, reject.
        return null;
    }
    // parse out text
    let fieldsSplit = decryptedText.split(sep).map(field => field.split('='));
    return fieldsSplit.reduce((ac, item) => {
        let [key, value] = item;
        if (key) {
            ac[key] = value;
        }
        return ac;
    }, {});
}

/**
 * Validate token timeout
 * @param timestamp
 * @param timeoutInMin
 * @return {boolean} true if valid; otherwise, throws Error
 */
function validateTokenTimeout(timestamp, timeoutInMin) {
    if (!timestamp) {
        throw new Error('No timestamp');
    }
    if (typeof timestamp === 'string') {
        if (!/^[0-9]+$/.test(timestamp)) {
            throw new Error('Invalid timestamp');
        }
        timestamp = +timestamp;
    }
    if (typeof timestamp !== 'number') {
        throw new Error('Invalid timestamp');
    }
    const now = Date.now();
    const timeOutInMs = +timeoutInMin * 60 * 1000;
    const diff = Math.abs(now - timestamp);
    if (diff > timeOutInMs) {
        throw new Error(`Timestamp: ${moment(timestamp)} outside of valid timeout range of ${timeoutInMin} minutes`);
    }
    return true;
}

/**
 * Hash text using SHA2 algorithm. Return in requested encoding,
 * default to base64.
 * @param str
 * @param encoding default base64
 */
function sha2hash(str, encoding) {
    const hash = crypto.createHash('sha256');
    hash.update(str);
    return hash.digest(encoding || 'base64');
}

/**
 * Hash text using pbkdf2Sync algorithm.
 *
 * @param str
 * @param encoding default base64
 */
function pbkdf2SyncHash(text, encoding, salt, iteration) {
    const key = crypto.pbkdf2Sync(text, salt, iteration, 32, encoding);
    return key.toString('hex');
}

/**
 * This is an equivalent of JCEUtils.hashId(long,String...) and JCEUtils.hashId(String,String...) java functions.
 * If the id is a number (long), it is first converted to the hex string,
 * which is then used in the second #hash function, together with salt.
 *
 * [PROD-3809] - added optional salt, which had no effect unless ID_HASH_KEY is not blank (no matter anymore);
 * [DEVSEC-2219] - salt is now used regardless ID_HASH_KEY;
 *
 * @param id - payment id, account id or number, user id
 * @param salt - extra values that affect the result, making it hard for someone to calculate from the id
 * @return {String} hash of the supplied id
 */
function hashId(id, ...salt) {
    //fail fast if illegal/empty/0 id
    if (typeof id !== 'string' && typeof id !== 'number') {
        return null;
    }

    if (!id || id === '0' || +id === 0) {
        return null;
    }

    //if id is a number, convert it to hex string
    const strId = (typeof id === "number") ? id.toString(16) : String(id);

    // use ID_HASH_KEY environment property unless it's undefined or blank
    const idHashKey = module.exports.getIdHashKey(); //(module.exports prefix is for Sinon stub to work, unit tests)
    let key = (idHashKey && idHashKey.trim().length > 0) ? idHashKey : DEFAULT_ID_HASH_KEY;

    if (salt.length > 0) {
        let filtered = salt.filter(s => s !== null && s !== undefined && s !== ''); //skip empty/null/undefined
        if (filtered.length > 0) {
            filtered.push(key); //add the env specific key to the end
            key = filtered.join('|');
        }
    }

    //no pipe '|' between id and key is intentional (same as in java)
    return sha1hash(strId + key)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");
}

/**
 * Checks if actual id hash matches given pre-calculated one.
 *
 * @param id identifier to validate the id/hashedId pair
 * @param hashedId
 * @param salt
 * @returns {boolean} true when hashes match
 */
function isValidHashedId(id, hashedId, ...salt) {
    if (!hashedId || !id) {
        return false;
    }
    //first, validate as Number (e.g., account/payment/user id); then, validate as String (account number, docket id)
    return hashId(+id, ...salt) === hashedId || hashId(String(id), ...salt) === hashedId;
}

/**
 * Return environment property ID_HASH_KEY value.
 * @return {string}
 */
function getIdHashKey() {
    return process.env.ID_HASH_KEY;
}

/**
 *
 * @param str
 * @param encoding
 * @returns {Buffer | string}
 */
function sha1hash(str, encoding) {
    const hash = crypto.createHash('sha1');
    hash.update(str);
    return hash.digest(encoding || 'base64');
}

/**
 * Encrypts the document using client-side encryption.
 *
 * @param {string} cryptKey The static encryption key.
 * @param {string|Buffer} content The unencrypted content.
 * @return {Object} An object containing encrypted content and metadata, {Metadata: {object}, Body: {string}}
 */
function clientEncrypt(cryptKey, content) {
    const contentIsBuffer = content && content instanceof Buffer,
        contentIsString = content && typeof content === 'string';

    if (!contentIsBuffer && !contentIsString) {
        throw new Error('content is empty or not a string');
    }

    const contentLength = content.length;
    // prepare encrypted key and random IV
    const byteAmzKey = crypto.randomBytes(32);
    const byteIV = crypto.randomBytes(16);

    let cipher = crypto.createCipheriv('aes-128-ecb', Buffer.from(cryptKey, 'hex'), '');
    let encryptedKey = cipher.update(byteAmzKey, 'buffer', 'hex');
    encryptedKey += cipher.final('hex');

    // allocate cipher for content encryption
    cipher = crypto.createCipheriv('aes-256-cbc', byteAmzKey, byteIV);
    let encryptedContent = cipher.update(content, (contentIsBuffer ? 'buffer' : 'utf-8'), 'buffer');
    let finalContent = cipher.final('buffer');
    encryptedContent = Buffer.concat([encryptedContent, finalContent]);

    let metadata = {};
    metadata[AMZ_KEY] = Buffer.from(encryptedKey, 'hex').toString('base64');
    metadata[AMZ_IV] = byteIV.toString('base64');
    metadata[AMZ_CONTENT_LENGTH] = '' + contentLength;
    return {'Body': encryptedContent, 'Metadata': metadata};
}

/**
 * Decrypts the document using client-side encryption.
 * @param {string} cryptKey The static encryption key.
 * @param {object} content The encrypted content, {Metadata: {object}, Body: {string}}
 */
function clientDecrypt(cryptKey, content) {
    const metadata = content.Metadata;
    // identify key, and iv
    const amzKey = metadata[AMZ_KEY],
        amzIV = metadata[AMZ_IV],
        amzContentLength = +metadata[AMZ_CONTENT_LENGTH];
    if (!amzKey || !amzIV) {
        throw new Error("Missing encryption keys");
    }
    // Decrypt key first
    let decipher = crypto.createDecipheriv('aes-128-ecb', Buffer.from(cryptKey, 'hex'), '');
    let decryptedKey = decipher.update(Buffer.from(amzKey, 'base64'), 'base64', 'hex');
    decipher.final();
    // We don't need to call decipher.final(), there is nothing lef to decrypt.
    let byteIV = Buffer.from(amzIV, 'base64');
    let byteKey = Buffer.from(decryptedKey, 'hex');
    let bodyType = typeof content.Body;

    // now decipher the result
    decipher = crypto.createDecipheriv('aes-256-cbc', byteKey, byteIV);
    let byteContent = content.Body;
    let contentIsBuffer = (byteContent && byteContent instanceof Buffer);
    let contentIsArray1 = (byteContent && byteContent instanceof Array && byteContent.length && byteContent[0] instanceof Buffer);
    let contentIsString = (byteContent && typeof byteContent === 'string');
    if (contentIsString) {
        byteContent = Buffer.from(byteContent.toString(), 'utf-8');
    } else if (contentIsArray1) {
        byteContent = byteContent[0];
    } else if (contentIsBuffer) {
        // take it
    } else {
        throw new Error('Unrecognized Body type: ' + bodyType);
    }
    // Build up content as a buffer
    let decryptedContent = decipher.update(byteContent, 'buffer', 'buffer');
    let finalContent = decipher.final('buffer');
    decryptedContent = Buffer.concat([decryptedContent, finalContent], amzContentLength);
    // reset the length of the data to what is present
    return decryptedContent;
}

function ascii2hex(str) {
    let arr = [];
    for (let i = 0; i < str.length; i++) {
        let hex = Number(str.charCodeAt(i)).toString(16);
        arr.push(hex);
    }
    return arr.join('');
}

function hex2ascii(hexx) {
    let hex = hexx.toString();//force conversion
    let str = '';
    for (let i = 0; i < hex.length; i += 2) {
        str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    }
    return str;
}

/**
 * Create HMAC digest of provided string. Return in requested encoding, default to hex.
 * @param key
 * @param content
 * @param encoding
 * @param isHexKey
 * @return {Buffer | string}
 */
function hmacHash(key, content, isHexKey, encoding) {
    let hashKey = isHexKey ? hex2ascii(key) : key;
    const salt = Buffer.from(hashKey, 'utf-8');
    const hmac = crypto.createHmac('sha256', salt);
    hmac.update(content);
    return hmac.digest(encoding || 'hex');
}

function hmacMd5Hash(key, content, isHexKey, encoding) {
    let hashKey = isHexKey ? hex2ascii(key) : key;
    const hmac = crypto.createHmac('md5', hashKey);
    hmac.update(content);
    return hmac.digest(encoding || 'hex');
}

/**
 * Create HMAC digest of provided string. Return in requested encoding, default to hex.
 * @param {String} key - binary key encoded as hex string (salt).
 * @param {String} content - content to hash
 * @param {String} encoding - output encoding type, default is hex
 * @return {Buffer | string}
 */
function hmacHashHex(key, content, encoding) {
    const salt = Buffer.from(key, 'hex');
    const hmac = crypto.createHmac('sha256', salt);
    hmac.update(content);
    return hmac.digest(encoding || 'hex');
}

/**
 * Encrypt content using AES/CBC. Note we expect content to be mod 32.
 * Note that node.js uses pck7 padding and always add padding.
 * @param {String|Buffer} content
 * @param {String} hexKey
 * @param {String} hexIv
 * @returns {Buffer}
 */
function encryptAes256CBC(content, hexKey, hexIv) {
    const contentPadded = padRightToMod(content, 16, '\0');
    const byteContent = Buffer.from(contentPadded, 'utf-8');
    const byteKey = Buffer.from(hexKey, 'hex');
    const byteIv = Buffer.from(hexIv, 'hex');
    const cipher = crypto.createCipheriv('aes-256-cbc', byteKey, byteIv);
    let encryptedContent = cipher.update(byteContent, 'buffer', 'buffer');
    let finalContent = cipher.final('buffer');
    encryptedContent = Buffer.concat([encryptedContent, finalContent]);
    return encryptedContent.toString('base64');
}

/**
 * Encrypt content with iv, then add hash and iv to the result.
 * @param content
 * @param hexKey
 * @param hexIv
 * @return hexIv.base64(content-encrypted).base64(sha256(hexIv.base64(content-encrypted)))
 */
function encryptAes256Hmac(content, hexKey, hexIv) {
    const c = encryptAes256CBC(content, hexKey, hexIv);
    const ivAndContent = hexIv + '.' + c;
    const hash = hmacHashHex(hexKey, ivAndContent, 'base64');
    return ivAndContent + '.' + hash;
}

/**
 *
 * Encrypts the payload and prepends the initialization vector (IV) to the
 * hex encoded String we generate.
 *
 * This function should be identical to TokenizationUtils.java#encryptAesCbcIvAndHex
 *
 * @param plainContent
 * @param key - expected as 32 utf8 characters
 * @param iv - (optional) expected as 16 utf8 characters
 */
function encryptAesCbcIvAndHex(plainContent, key, iv = null) {
    if (!iv) {
        // Note, each byte is represented as 2 utf8 characters.
        // Therefore, the length of iv will be 16 characters
        iv = crypto.randomBytes(8).toString('hex').toUpperCase();
    }

    // encrypt with hex + iv
    const hexKey = Buffer.from(key, 'utf8').toString('hex');
    const hexIv = Buffer.from(iv, 'utf8').toString('hex').toUpperCase();
    const encBase64 = encryptAes256CBC(plainContent, hexKey, hexIv);

    // format the output and concatenate with iv
    const encHex = Buffer.from(encBase64, 'base64').toString('hex').toUpperCase();

    return hexIv + encHex;
}

/**
 * Parse the initialization vector (IV) from the payload and perform the aes CBC decryption.
 *
 * This function should be identical to TokenizationUtils.decryptAesCbcIvAndHex
 *
 * @param encryptedContent
 * @param key
 */
function decryptAesCbcIvAndHex(encryptedContent, key) {
    let ivHex = encryptedContent.substring(0, 32);
    let tokenStr = encryptedContent.substring(32, encryptedContent.length);

    const keyHex = Buffer.from(key, 'utf8').toString('hex');
    const encBase64 = Buffer.from(tokenStr, 'hex').toString('base64');

    return decryptAes256CBC(encBase64, keyHex, ivHex);
}

/**
 * This method will create a string of the form
 * key1=value1[pairSeparator]key2=value2. This string will then be encrypted
 *  with the supplied key and adds HMAC authentication.
 * Throws exception if the value map or the key is empty or null
 *
 * The input map should be a flat-map/one-level map, for e.g.
 * {
 *  "notificationId": "1234",
 *  "header.accountNumber": '6759370',
 *  "header.amount": '11'
 * }
 * @param {Map} content - Map of values to encrypt
 * @param {String} hexKey - key to encrypt with and produce hmac with
 * @param {String} tokenPairSeparator
 * @returns {string} - return encrypted string
 */
function encryptAes256HmacWithInputAsMap(content, hexKey, tokenPairSeparator = ';') {
    if (!content || Object.keys(content).length === 0) {
        throw new Error('List of input values was empty or null');
    }
    if (!hexKey) {
        throw new Error('Crypt key was not supplied');
    }

    let tokenList = createTokenList(content, tokenPairSeparator);
    //Generate random IV
    const byteIv = crypto.randomBytes(16);
    let hexIv = byteIv.toString('hex');

    return encryptAes256Hmac(tokenList, hexKey, hexIv);
}

/**
 * This method will create a string of the form
 * key1=value1[pairSeparator]key2=value2
 *
 * The input map should be a flat-map/one-level map, for e.g.
 * {
 *  "notificationId": "1234",
 *  "header.accountNumber": '6759370',
 *  "header.amount": '11'
 * }
 *
 * @param {Map} content - Map of values to encrypt
 * @param {String} pairSeparator - to separate key value pairs
 * @returns {string} - return string of the form key1=value1[pairSeparator]key2=value2
 */
function createTokenList(content, pairSeparator = ';') {
    if (!content || Object.keys(content).length === 0) {
        throw new Error('List of values must not be empty');
    }

    let token = [];

    Object.entries(content).map(([key, value]) => {
        token.push(key + '=' + value);
    });

    return token.join(pairSeparator);
}

/**
 * Decrypt content using AES/CBC. Note we expect content to be mod 32.
 * @param {String} content in base64
 * @param {String} hexKey
 * @param {String} hexIv
 * @returns {String}
 */
function decryptAes256CBC(content, hexKey, hexIv) {
    const byteKey = Buffer.from(hexKey, 'hex');
    const byteIv = Buffer.from(hexIv, 'hex');
    const byteContent = Buffer.from(content, 'base64');

    const decipher = crypto.createDecipheriv('aes-256-cbc', byteKey, byteIv);
    let decryptedContent = decipher.update(byteContent, 'buffer', 'buffer');
    let finalContent = decipher.final('buffer');
    decryptedContent = Buffer.concat([decryptedContent, finalContent]);
    return decryptedContent.toString('utf-8').replace(/\0/g, '');
}

/**
 * Decrypt content generated by the algorithm in encryptAes256Hmac.
 * @param content
 * @param hexKey
 * @return {String} return null in case validation failure.
 */
function decryptAes256Hmac(content, hexKey) {
    let p = (content || '').split('.');
    if (!p || p.length !== 3) {
        return null;
    }
    const hexIv = p[0],
        encryptedContent = p[1],
        hmac = p[2];
    const hmacComputed = hmacHashHex(hexKey, hexIv + '.' + encryptedContent, 'base64');
    if (hmacComputed !== hmac) {
        return null;
    }
    return decryptAes256CBC(encryptedContent, hexKey, hexIv);
}

/**
 * This method will decrypt the supplied token using AES CBC algorithm and validates HMAC authentication
 * and convert key-value pairs of the form key1=value1[pairSeparator]key2=value2 into a map
 * Throws exception if the token/crypt key supplied is empty or null
 *
 * @param {String} content - text to decrypt
 * @param {String} hexKey - key to decrypt with and validate hmac with
 * @param {String} tokenPairSeparator
 * @return {Map} - return map of decrypted values or null in case of validation failure.
 * The decrypted map will be flat-map/one-level map.
 * e.g. {"notificationId":"1234","header.accountNumber":"6759370","header.amount":"11"}
 *
 */
function decryptAes256HmacAndReturnMap(content, hexKey, tokenPairSeparator = ';') {

    if (!content) {
        throw new Error('Cypher text was not supplied');
    }

    if (!hexKey) {
        throw new Error('Crypt key was not supplied');
    }

    let decryptedToken = decryptAes256Hmac(content, hexKey);

    if (!decryptedToken) {
        throw new Error('Decrypted token is empty, possibly due to bad format of token or HMAC not matching');
    }

    return createValueMap(decryptedToken, tokenPairSeparator)
}

/**
 * This method will parse a string of the form key1=value1[pairSeparator]key2=value2 into a map
 *
 * @param {String} content
 * @param {String} pairSeparator
 * @returns {Map} - return map of decrypted values or null in case of validation failure.
 * The decrypted map will be flat-map/one-level map.
 * e.g. {"notificationId":"1234","header.accountNumber":"6759370","header.amount":"11"}
 *
 */
function createValueMap(content, pairSeparator = ';') {

    if (!content) {
        throw new Error('Token must not be empty');
    }

    const pairs = content.split(pairSeparator);
    if (!pairs || pairs.length === 0) {
        throw new Error('Token does not contain key-value pairs separated by: ' + pairSeparator);
    }

    let values = {};

    for (let i = 0; i < pairs.length; i++) {
        let pairToken = pairs[i]
        let pair = pairToken.split("=");
        if (!pair || pair.length !== 2) {
            // if a token pair is not in the correct format then ignore it
            // and continue to the next token
            continue;
        }
        let key = pair[0].trim();
        let value = pair[1].trim();
        values[key] = value;
    }
    return values;
}

/**
 Utility method which encrypts the supplied string using CBC encryption
 and SHA-1 Algo
 @param {string} token
 @param {string} hexKey
 @param {string} salt
 @param {string} iv
 @param {number} iterations
 @returns {string}
 */
function rijndaelEncryptCBCSHA1(token, hexKey, salt, iv, iterations) {
    if (!token) {
        return null;
    }
    const saltValueBytes = Buffer.from(salt);
    const keyBytes = getShaEncryptedKey(hexKey, saltValueBytes, iterations, 16);
    const secretKey = crypto.createCipheriv('aes-128-cbc', keyBytes, iv);
    return secretKey.update(token, 'utf8', 'base64') + secretKey.final('base64');
}
/**
 Method to create secret key using PBKDF1 algo
 @param {string} password
 @param {Buffer} salt
 @param {number} iterations
 @param {number} requested
 @returns {Buffer}
 */

function getShaEncryptedKey(password, salt, iterations, keyLength) {

    let seed = Buffer.concat([Buffer.from(password), salt]);
    const derivedKey = Buffer.alloc(keyLength);
    for (let i = 0; i < iterations; i++) {
        const hashFunc = crypto.createHash('sha1');
        hashFunc.update(seed);
        seed = hashFunc.digest();
    }
    seed.copy(derivedKey, 0, 0, keyLength);

    return derivedKey;

}


/**
 * Generate AES 128 bit shared key.
 * Same code as in Java.
 * @return {string} - generated key in hex format.
 */
function generateAESKey() {
    // 16*8 = 128
    let key = crypto.randomBytes(16);
    return key.toString('hex');
}

/**
 * Generate wrapped AES 128 bit key
 * @returns {String}
 */
function generateWrappedAESKey() {
    return wrapKey(generateAESKey());
}

/**
 * Generate JWT key of specific size, to be used with HS256 algorithm.
 * Use crypto.randomBytes and then map each byte
 * to alfa numeric
 * @param {number} size
 * @returns {string}
 */
function generateJwtKey(size) {
    const charSet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@#-+%.:';
    return generateRandomString(charSet, size);
}

/**
 * Generate wrapped JWT key.
 * @param {Number} size
 * @returns {String}
 */
function generateWrappedJwtKey(size) {
    return wrapKey(generateJwtKey(size))
}

/**
 * Generate a random string using the provided characters
 * Use crypto.randomBytes and then map each byte
 * to alfa numeric
 * @param {string} charSet - list of characters used
 * @param {number} size - length of the random string
 * @returns {string}
 */
function generateRandomString(charSet, size) {
    const len = charSet.length;
    const mapChar = (nr) => charSet.charAt(nr % len);
    let bytes = crypto.randomBytes(size);
    let charArr = [];
    for (let b of bytes) {
        charArr.push(mapChar(b));
    }
    return charArr.join('');
}

/**
 * Configuration for a single key
 * @typedef {Object} KeyConfiguration
 * @property {string} alg
 * @property {string} kid
 * @property {string} key
 * @property {string[]} scope - optional scope restriction
 * @property {number} ttl - Time to live for token generate with this key
 *
 */

/**
 * Object to configure TLA in API gateway
 * @typedef {Object} VaultSecret
 * @property {string} [alg] - algorithm for JWT keys (only HS256 for now).
 * @property {string} [tla] -
 * @property {string} currentAccessTokenKeyId
 * @property {string[]} defaultScope
 * @property {Object.<string,KeyConfiguration>} requestKeys
 * @property {Object.<string,KeyConfiguration>} accessTokenKeys
 */

/**
 * Generate a secret configuration for a TLA.
 * @param {string} tla
 * @param {string[]} scope
 * @param {string} alg - currently only HS256
 * @param {string} firstKey -
 * @param {number} nrOfRequestKeys
 * @param {number} requestTtl
 * @param {number} nrOfAccessKeys
 * @param {number} accessTtl
 * @returns {VaultSecret}
 */
function generateVaultSecret({
                                 tla, scope, alg = 'HS256',
                                 firstKey,
                                 nrOfRequestKeys = 1, requestTtl = 300,
                                 nrOfAccessKeys = 1, accessTtl = 360
                             }) {
    /** @type VaultSecret */
    let secret = {
        tla,
        currentAccessTokenKeyId: '001',
        defaultScope: scope,
        requestKeys: {},
        accessTokenKeys: {}
    };
    for (let i = 1; i <= nrOfRequestKeys; i++) {
        const kid = utils.pad(`${i}`, 3, '0', true)
        const key = (i === 1 && firstKey)
            ? firstKey
            : generateJwtKey(31);
        // kid, key, alg, ttl: requestTtl
        secret.requestKeys[kid] = {
            kid, key, alg, ttl: requestTtl
        }
    }
    for (let i = 1; i <= nrOfAccessKeys; i++) {
        const kid = utils.pad(`${i}`, 3, '0', true)
        const key = generateJwtKey(31);
        secret.accessTokenKeys[kid] = {
            kid, key, alg, ttl: accessTtl
        }
    }
    return secret;
}


module.exports = {
    wrapKey: wrapKey,
    unwrapKey: unwrapKey,
    // Do not use
    wrapKeyExt: wrapKeyExt,
    unwrapKeyExt: unwrapKeyExt,
    unwrapExtIfNeeded: unwrapExtIfNeeded,
    wrap: wrapKey,
    unwrap: unwrapKey,
    isWrapped,
    unwrapFields: unwrapFields,
    wrapFields,
    unwrapIfNeeded: unwrapIfNeeded,
    encrypt: encrypt,
    decrypt: decrypt,
    padLeft: padLeft,
    padRight: padRight,
    padCenter: padCenter,
    space: space,
    sha2hash: sha2hash,
    pbkdf2SyncHash: pbkdf2SyncHash,
    sha1hash: sha1hash,
    hmacHash: hmacHash,
    hashId,
    getIdHashKey,
    hmacMd5Hash: hmacMd5Hash,
    isValidHashedId: isValidHashedId,
    clientEncrypt: clientEncrypt,
    clientDecrypt: clientDecrypt,
    decryptToMap,
    validateTokenTimeout,
    encryptAesCbcIvAndHex,
    decryptAesCbcIvAndHex,
    encryptAes256CBC,
    decryptAes256CBC,
    encryptAes256Hmac,
    decryptAes256Hmac,
    encryptAes256HmacWithInputAsMap,
    createTokenList,
    decryptAes256HmacAndReturnMap,
    createValueMap,
    hmacHashHex,
    encryptCBCSHA1: rijndaelEncryptCBCSHA1,
    generateAESKey,
    generateWrappedAESKey,
    generateJwtKey,
    generateWrappedJwtKey,
    generateVaultSecret,
    generateRandomString
};
