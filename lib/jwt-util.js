const jwt = require('jwt-simple');
const {unwrap} = require('./crypt-utils');

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
        if (!options.secretKey) {
            throw new Error("No private/public key or secret key provided to JWTUtil.constructor.");
        }

        this.secretKey = options.secretKey;
    }

    /**
     * Encode JSON payload
     * @param {Object} payload
     * @returns {String}
     */
    encode(payload) {
        if (!this.secretKey) {
            throw new Error("JWTsecret key is missing, can't encode payload.");
        }
        if (!payload) {
            throw new Error("JWT payload must be a string, Buffer, ArrayBuffer, Array, or array-like object")
        }

        const options =  {};

        return jwt.encode(payload, this.secretKey, this.algorithm, options);

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
        console.log("decode reunning")
        if (!this.secretKey) {
            throw new Error("secret key is missing, can't decode payload.");
        }
        if (!jwtString) {
            throw new Error("JWT not provided");
        }

        return jwt.decode(jwtString, this.secretKey, noVerify, this.algorithm);

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

        const jwtSecretKey = unwrap(options.jwtSecretKey);
        // const jwtSecretKey = options.jwtSecretKey;

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


    validateJwt(req, res, next) {
        const log = req.log,
            options = this.options,
            cache = this.cache;

        let authHeader = req.headers.authorization || '';
        console.log("authheader", authHeader)

        let jwt = authHeader.split("Bearer ").pop();

        if (!jwt) {
            log.error(`The Authorization HTTP header was not populated or it is different than Bearer. Raw Authorization header: ${authHeader}`);
            return res.status(400).send({errorCode: "auth.jwt.missing", message: 'Authorization missing'});
        }
        req.headers.jwtToken = jwt

        next();
    }

}


module.exports = JWTUtil;
