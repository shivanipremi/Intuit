const jwt = require('jwt-simple');
// const {unwrap} = require('./crypt-utils');

/**
 * Wrapper class for jwt-simple to add reading public/private keys from file system.
 */
class JWTUtil {

    /**
     * @param {Object} log
     * @param {Object} options - config options
     * @param {String} options.kid - key id
     * @param {String} options.algorithm - algorithm used in JWT
     * @param {String} options.publicKey - public key in PEM format
     * @param {String} options.privateKey - private key in PEM format
     * @param {String} options.passPhrase unwrapped pass phrase for private key
     *
     * Use secretKey only for symmetric-key algorithm
     * Use publicKey/privateKey for asymmetric key algorithm
     */
    constructor(log, options) {
        options = options || {};
        this.log = log;

        if (!options.algorithm) {
            throw new Error("Mandatory algorithm parameter not provided to JWTUtil.constructor.");
        }
        this.algorithm = options.algorithm;

        // We need to have at least one of private/public key
        if (!options.privateKey && !options.publicKey && !options.secretKey) {
            throw new Error("No private/public key or secret key provided to JWTUtil.constructor.");
        }
        const preparePem = (text) => (text || '').replace(/\\n/g, '\n');
        // public key is optional?
        if (options.publicKey) {
            this.publicKey = preparePem(options.publicKey);
        }

        if (options.privateKey) {
            if (options.passPhrase) {
                // when we have passPhrase, send key as an object
                this.privateKey = {
                    key: preparePem(options.privateKey),
                    passphrase: options.passPhrase
                };
            } else {
                this.privateKey = preparePem(options.privateKey);
            }
        }

        this.secretKey = options.secretKey;
        this.kid = options.kid;
    }

    /**
     * Encode JSON payload
     * @param {Object} payload
     * @returns {String}
     */
    encode(payload) {
        if (!this.privateKey && !this.secretKey) {
            throw new Error("JWT private key or secret key is missing, can't encode payload.");
        }
        if (!payload) {
            throw new Error("JWT payload must be a string, Buffer, ArrayBuffer, Array, or array-like object")
        }

        const options = this.kid ? {header: {kid: this.kid}} : {};

        if (this.privateKey) {
            return jwt.encode(payload, this.privateKey, this.algorithm, options);
        } else {
            return jwt.encode(payload, this.secretKey, this.algorithm, options);
        }
    }

    /**
     * Decode jwt string
     * @param {String} jwtString - JWT string to decode
     * @param {Boolean} noVerify - when true, decode without verification.
     * @returns {Object} - payload
     * @throws Error('Algorithm not supported')
     * @throws Error('Signature verification failed')
     * @throws Error('Token not yet active')
     * @throws Error('Token expired')
     */
    decode(jwtString, noVerify = false) {
        if (!this.publicKey && !this.secretKey) {
            throw new Error("Public key or secret key is missing, can't decode payload.");
        }
        if (!jwtString) {
            throw new Error("JWT not provided");
        }
        if (this.publicKey) {
            return jwt.decode(jwtString, this.publicKey, noVerify, this.algorithm);
        } else {
            return jwt.decode(jwtString, this.secretKey, noVerify, this.algorithm);
        }
    }

    /**
     * Prepare jwt options from an options object
     * @param {Object} options
     * @param {String} options.jwtKeyId - KID field in JWT
     * @param {String} options.jwtSecretKey - wrapped/base64 secret key.
     * @param {String} options.jwtAlg - JWT algorithm default HS256
     * @returns {{secretKey: string, kid: *, algorithm: (string|String)}}
     */
    static prepareJwtOptions(options) {
        if (!options.jwtSecretKey) {
            throw new Error('JWT Secret Key is missing from arguments');
        }
        if (!options.jwtKeyId) {
            throw new Error('JWT Key ID is missing from arguments');
        }
        // const jwtSecretKey = unwrap(options.jwtSecretKey);
        const jwtSecretKey = options.jwtSecretKey;

        const secretKey = Buffer.from(jwtSecretKey, 'base64').toString('utf-8');
        const algorithm = options.jwtAlg || 'HS256';

        return {
            algorithm,
            secretKey,
            kid: options.jwtKeyId
        };
    }

    /**
     * Extract JWT header, without any further checks
     *
     * @param {String} token - JWT Token
     * @returns {Object} - parsed out header
     */
    static getJwtHeader(token) {
        // check segments
        const segments = token.split('.');
        if (segments.length !== 3) {
            throw new Error('JWT had wrong number of segments (should be 3).');
        }

        // All segment should be base64
        const headerSeg = segments[0];

        // base64 decode and parse JSON
        const decodeSeg = Buffer.from(headerSeg, 'base64').toString('utf-8');
        return JSON.parse(decodeSeg);
    }

}


module.exports = JWTUtil;
