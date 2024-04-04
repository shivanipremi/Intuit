"use strict";
/**
 * Base API service providing essential routes for an object schema, and common implementation.
 * Behaviour is customized through overridden functions designed for model specific queries,
 * however the route handler functions should not change.
 *
 * An API service should define an apiModel in its constructor. eg.
 * this.apiModel = Identity;
 * this.apiLabel = 'Identity-ms:';
 */
const
    {
        ExpressApp, initDefaultOptions, initialize, initStatsD, initValidateOptions, parseIntParam
    } = require('./service-base-v2'),
    // {param, query, validationResult} = require('express-validator/check'),
    JWTUtil = require('../../lib/jwt-util'),
    Ajv = require('ajv'),
    {initMongoClient, initMongoDb, appendMongoDbOptions} = require('../../lib/mongodb/mongodb-utils');


function initApiOptions(defaultPort) {
    const removeTailSlash = (str) => removeTail(str || '', '/');
    let commander = initDefaultOptions(defaultPort)
        .option('--default-route <mount-path>', 'Path to prefix all URLs (other then alive)', '/api/v1');
    return appendMongoDbOptions(commander);
}

/**
 * Purpose of this function is to provide an easy way to grep for
 * catalog of all error conditions and error messages.
 * Reference taken from: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/errors-overview.html
 * @param {Number} status - http status code
 * @param {String} errorCode - string error code
 * @param {String} message - description of error
 * @param {String} upstream - array of errors from upstream api call
 * @returns {{status: Number, content: {errorCode: String, message: String}}}
 */
const createErrorResponse = (status, errorCode, message, upstream = undefined) => ({
    status,
    content: {
        errorCode,
        message,
        ...(upstream ? {upstream} : {})
    }
});

/**
 * Return a success response.
 * By default, sends back an empty response.
 *
 * @param content
 * @returns {{content, status: number}}
 */
const createSuccessResponse = (content = undefined) => ({
   status: 200,
   content
});

async function initApiResources(options) {
    return await initialize(options)
        // make sure mandatory options are present
        .then(initValidateOptions('mongoUrl', 'mongoUser', 'mongoPassword'))
        .then(initMongoDb)
        // .then(initStatsD)
}

/**
 * Base class for PayApi micro services.
 * Using mongodb client.
 */
class PayApiBaseApp extends ExpressApp {
    constructor(context) {
        super(context);
        this.mongoClient = context.mongoClient;
        this.db = context.db;
    }

    /**
     * Setup the final error handling routes.
     * @param app
     */
    registerErrorRoutes(app) {
        const {log} = this;
        // setup error handling. This needs to be at the bottom of
        // the chain. It also needs to have 4 parameters.
        app.use((err, req, res, next) => {
            let returnData = {error: err.message || 'Unexpected error'};
            if (err && err.stack) {
                log.warn(`Request[${req.id}]: Express error handling: ${JSON.stringify(returnData)}`, err, {});
            } else {
                let error;
                try {
                    error = JSON.stringify(err);
                } catch (jsonErr) {
                    log.error(`Failed to convert error to string using JSON.stringify, using util.inspect instead`, jsonErr, {});
                    error = inspect(err);
                }

                log.warn(`Request[${req.id}]: Express error handling: ${JSON.stringify(returnData)}, err=${error}`);
            }
            // Return message, we expect here err to be an exception
            // with message field plain text.
            res.status(500).json(returnData);
        });

        // If no route found by now, it's 404 error
        app.use('*', (req, resp) => {
            // Map other paths to 404
            log.info(`Request[${req.id}]: ${req.method} ${req.originalUrl} route not found`);
            resp.status(404).json({error: 'Route not found'});
        });
    }

    /**
     * Generate the audit request tags, that accompany statsd 'rs_time' measurements on response telemetry.
     * auditRequestTags() default behaviour is good enough.
     */

    /**
     * Extend close to shutdown mongodb client.
     * @param callback
     * @returns {*|*}
     */
    close(callback) {
        const _close = async () => {
            await super.close();
            if (this.mongoClient) {
                this.log.info('Closing mongoDB client');
                await this.mongoClient.close();
                this.log.info('MongoDB client closed');
            }
        };
        return ExpressApp.doCallbackOrPromise(_close(), callback);
    }




    /**
     * Express middleware to check validation results if needed.
     * Issue status 422 in case validation fails.
     * @param req The request
     * @param res The response
     * @param next Function to continue request chain
     */
    static checkValidationResults(req, res, next) {
        const log = req.log,
            errors = validationResult(req);

        if (errors.isEmpty()) {
            next();
        } else {
            const mapped = errors.mapped();
            log.info(`Request[${req.id}]: parameters did not pass validation ${JSON.stringify(mapped)}`);
            res.status(422).json({errorCode: 'validation.error', message: mapped});
        }
    }

    /**
     * Generate final express middleware around an async class method.
     * Method is expected to return object with status, content.
     * @param {Function} method - Async method
     * @returns {Function}
     */
    invokeAsync(method) {
        return (req, res, next) => {
            // call the method expected to return promise, resolves to {status, content}
            method.call(this, req, res.locals.result)
                .then(result => {
                    const log = req.log,
                        status = result.status || 200;

                    if (![200, 202, 203, 204].includes(status)) {
                        log.warn('Returning non ok result (%s): %s', status, JSON.stringify(result.content));
                    }
                    if (result.header) {
                        res.set(result.header);
                    }
                    res.status(status).json(result.content);
                })
                .catch(err => next(err));
        };
    }

    /**
     * Initialize JSON Schema validator.
     */
    initSchemaValidator(schemaConfig) {
        console.log("schema config", schemaConfig)
        const {log} = this;
        this.schemaValidator = {};
        // Iterate through the partner definitions, generating a validator
        // for each partner
        const defaultConfig = schemaConfig.default;
        for (let [partner, config] of Object.entries(schemaConfig)) {
            console.log("partner, c", partner, config)
            let v = {
                validator: new Ajv({allErrors: true})
            };
            const pConfig = {...defaultConfig, ...config};
            // load the validator with the defined schemas
            for (let [key, value] of Object.entries(pConfig)) {
                if (value && typeof value === "object") {
                    try {
                        console.log("value, key", {value, key})
                        v.validator.addSchema(value, key);
                    } catch (err) {
                        log.error('Invalid schema: %s:%s, %s', partner, key, JSON.stringify(value, null, 2));
                        throw err;
                    }
                } else if (typeof value === 'function') {
                    // copy over validator functions
                    v[key] = value;
                }
            }
            this.schemaValidator[partner] = v;
            console.log("this.schema validator", this.schemaValidator)
        }
    }

    /**
     * Create an express middleware validate function, that will validate the request against
     * the schema identified by id.
     * Expect the issuer to be set in the request.
     * @param {String} id - schema to validate against.
     * @returns {Function}
     */
    validateSchema(id) {
        return (req, resp, next) => {
            const {log, body} = req;
            // identify schema validator for the issuer
            const valConfig = this.schemaValidator['default'];
            if (!valConfig) {
                const msg = `No schema configuration defined for issuer (${issuer}) or default`;
                next(msg);
                return;
            }
            const validator = valConfig.validator;
            validator.validate(id, body);
            if (validator.errors) {
                const errorMsg = validator.errorsText();
                log.warn('Request validation failed: %s', errorMsg);
                resp.status(422).json({
                    errorCode: 'schema.validation.error',
                    message: `Invalid ${id} schema. See errors`,
                    errors: errorMsg
                });
                return;
            }
            // check for custom validate function...
            const valFn = valConfig['_' + id];
            if (typeof valFn !== 'function') {
                // No validate Fn, continue
                next();
                return;
            }
            const errorMsg = valFn(body);
            if (!errorMsg) {
                // no error from validate Fn, continue
                next();
                return;
            }
            log.warn('Request validation failed: %s', errorMsg);
            resp.status(422).json({
                errorCode: 'schema.validation.error',
                message: `Invalid ${id} schema. See errors`,
                errors: errorMsg
            });
        };
    }


}


module.exports = {
    initApiOptions,
    initApiResources,
    createErrorResponse,
    createSuccessResponse,
    initMongoClient,
    PayApiBaseApp
};