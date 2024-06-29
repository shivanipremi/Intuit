/**
 * Define a Master class to handle generic functionality of a micro-service.
 * Constructor expects the initialized context.
 * @module  service/service-base-v2
 */
const os = require('os'),
    path = require('path'),
    uuid = require('uuid'),
    u = require('url'),
    cookie = require('cookie'),
    express = require('express'),
    https = require('https'),
    // {validationResult} = require('express-validator/check'),
    xssFilters = require('xss-filters'),
    // iterator = require('object-recursive-iterator'),
    bodyParser = require('body-parser'),
    Promise = require('bluebird'),
    log = require('../logger'),
    commander = require('commander'),
    fs = require('fs'),
    JWTUtil = require('../../lib/jwt-util'),
    {unwrap} = require('../crypt-utils'),
    atob = require('atob'),
    moment = require('moment'),
    print = JSON.stringify;

const waitTime = async (timeInSec) => new Promise((resolve, _) => {
    setTimeout(resolve, timeInSec * 1000);
});

/**
 * @class Wrapper class to attach request id to the winston metadata.
 */
class LogExpress {
    constructor(log, request) {
        this.log = log;
        const cookies = request.cookies || {},
            headers = request.headers || {},
            partnerTla = request.partnerTla || headers['x-api-token-sub'];
        this.extraTags = {
            requestId: request.id,
            ...(partnerTla ? {partnerTla} : {})
        };
        // record session id from cookie or request header
        const sessionId = cookies.JSESSIONID || headers['x-session-id'];
        if (sessionId) {
            this.extraTags.sessionId = sessionId;
        }
        const methodNames = ['debug', 'info', 'warn', 'error', 'write'];
        const self = this;
        methodNames.forEach(name => {
            this[name] = function () {
                self._log(name, Array.prototype.slice.call(arguments));
            };
            this[name + 'Meta'] = function () {
                self._logMeta(name, Array.prototype.slice.call(arguments));
            };
        });
    }

    /**
     * Helper method to log with fixed metadata.
     * @param methodName
     * @param args
     * @private
     */
    _log(methodName, args) {
        // AWS.config.logger only works with log/write method
        if (methodName === 'write' && !this.log[methodName]) {
            methodName = 'info';
        }
        // add metadata for winston as the last parameter
        args.push(this.extraTags);
        this.log[methodName].apply(this.log, args);
    }

    /**
     * Helper method to log with explicit metadata. Last argument is the metadata.
     * @param methodName
     * @param args
     * @private
     */
    _logMeta(methodName, args) {
        // add metadata for winston as the last parameter
        const lastIndex = args.length - 1,
            hasMeta = (lastIndex > 0);
        let meta = (hasMeta ? args[lastIndex] : {});
        meta = Object.assign(meta, this.extraTags);
        if (hasMeta) {
            args[lastIndex] = meta;
        } else {
            args.push(meta);
        }
        this.log[methodName].apply(this.log, args);
    }

    isDebugEnabled() {
        return this.log.isDebugEnabled();
    }

    getRequestId() {
        return this.extraTags.requestId;
    }
}


/**
 * @class Wrapper class to attach request id and timing to the metadata.
 */
class TimeLogger extends LogExpress {
    constructor(log, request) {
        super(log, request);
        this.now = Date.now();
    }

    _log(methodName, args) {
        // add timing to the logs, using 3 digit second precision
        let timing = Date.now() - this.now;
        this.extraTags.timing = (timing / 1000).toFixed(3);
        super._log(methodName, args);
    }
}


/**
 * Express App base.
 * @class
 * @classDesc Express App base.
 * @export
 */
class ExpressApp {
    /**
     * Create an instance of Express App
     * @param  {Object} context The initialized context.
     * @return {ExpressApp}
     */
    constructor(context) {
        // save parameters
        this.options = context.options || {};
        this.log = context.log || log;
        this.nrOfRequestsInProgress = 0;

        const app = express(),
            router = express.Router();

        // initialize express
        this.express = express;
        this.app = app;
        this.router = router;
        this.defaultRoute = this.options.defaultRoute || '/';

        //  (this, StatsDMixin);

        // By default handle JSON and post format.
        const jsonLimit = this.options.jsonLimit || '100Mb';
        // parse request body as JSON, up to 100MB size
        // Note that the error in this case difficult to read.
        app.use(bodyParser.json({
            limit: jsonLimit, // limit to 100Mb the size, internal server
            ...(context.keepRawBody ? {  // Allow service to enable caching the rawBody, not only the json on req.body
                verify: (req, res, buf) => {
                    req.rawBody = buf;
                }
            } : {})
        }));

        // handle form...
        app.use(bodyParser.urlencoded({
            limit: jsonLimit, // limit to 100Mb the size, internal server
            extended: true
        }));
        this.appName = this.options.appName || path.basename(process.argv[1], '.js');
    }

    initErrorHandling() {
        // When running a micro service, we dont' want to shutdown for
        // and unhandled exception or promise.
        // Other type of node.js code that is ok (default behaviour of node.js).
        // utils.logProcessErrors(this.log);
    }

    /**
     * Run Express micro-service.
     */
    run() {
        console.log('Options will mask fields name ending : Password,Secret,SecretKey,Key,Cert,pass,Token,Passphrase');
        console.log('Running with options: %s', JSON.stringify(this.options));
        // this.initStatsDClient();
        this.init();
        this.initErrorHandling();
        this._initExpress();
        this.initTimers();
        this.startExpress();
        // setup graceful shutdown
        if (!process.env.TEST_MODE) {
            process.on('SIGTERM', () => this._shutdown());
            process.on('SIGINT', () => this._shutdown());
        }
        return this; // return the app
    }

    /**
     * override to initialize any properties that should be initialized as part of run()
     */
    init() {

    }

    /**
     * Override this method to hook in additional shutdown logic.
     * @returns {Promise<void>}
     */
    async shutdown() {
        // signal shutting down ...
        this.isShutdown = true;
        await this.close();
    }

    _shutdown() {
        // hook for graceful shutdown
        // const log = this.log;
        log.info('Got SIGTERM. Graceful shutdown start');
        // respond for x seconds before shutting down the
        // express server.
        waitTime(this.options.sigtermDelay || 5)
            .then(() => this.shutdown())
            .then(() => {
                log.info('Shutdown finished');
                process.exit();
            })
            .catch(err => {
                log.error('Shutdown failed with error', err, {});
                process.exit(1);
            });
    }


    /**
     * Implement /alive URL.
     * Note code for node.js cluster had been removed, this will always
     * return data for a single process. Keep the array for backward compatibility
     * of test cases.
     * If request has logResp in the query parameters, data will be recorded in the log
     * also allowing for
     * @param  {HttpRequest}   req
     * @param  {HttpResponse}  resp
     */
    handleAlive(req, resp) {
        if (this.isShutdown) {
            resp.status(500).json({message: 'Shutting down'});
            return;
        }
        const {log} = req;
        const logResp = req.query.logResp;
        const checkDB = (req.query.checkDB && this.oracledb && this.poolName && this.executeSql);
        const p = process.memoryUsage();
        let aliveData = {
            appName: this.appName,
            rss: p.rss,
            heapTotal: p.heapTotal,
            heapUsed: p.heapUsed,
            nrOfRequestsInProgress: this.nrOfRequestsInProgress - 1
        };
        if (this.oracledb && this.poolName) {
            // add connection info
            let pool = this.oracledb.getPool(this.poolName);
            if (pool) {
                aliveData.dbConInUse = pool.connectionsInUse;
                aliveData.dbConOpen = pool.connectionsOpen;
            }
        }
        if (logResp) {
            log.infoMeta('Alive status', aliveData);
        }
        if (!checkDB) {
            resp.json([aliveData]);
        } else {
            // do a database ping
            this.executeSql('select * from dual')
                .then(() => {
                    aliveData.dbAlive = true;
                })
                .catch(err => {
                    log.error('DB ping failed: ', err, {});
                })
                .then(() => {
                    resp.json([aliveData]);
                });
        }
    }

    /**
     * Init request parsers here, like add BSON processing.
     */
    _initExpressParsers() {
    }

    /**
     * Setup express application and start listening. This method is not intended to be overwritten.
     */
    _initExpress() {
        const log = this.log,
            router = this.router,
            app = this.app;

        // Disable etag. ETAG applies to static content
        // not for micro services that we implement here.
        // See: https://expressjs.com/en/4x/api.html#etag.options.table
        app.disable('etag');

        // first initialize any additional parsers
        this._initExpressParsers();

        // parse out cookies first
        app.use((req, resp, next) => {
            req.cookies = cookie.parse(req.headers.cookie || '');
            next();
        });

        // setup tracking
        app.use(this.trackRequests.bind(this));

        // sanitize body/params/query (TODO: cookies/headers?)
        // if (this.options.xssSanitize === 'IGNORE') {
        //     // log.warn('Sanitization disabled via option --xss-sanitize IGNORE');
        // } else {
        //     app.use(this.sanitizeAll.bind(this));
        // }

        // setup isAlive method
        /**
         * @openapi
         * /alive:
         *   get:
         *     description: Endpoint to provide a health-check for the app
         *     operationId: generic
         *     tags:
         *       - Health Check
         *     consumes:
         *       - none
         *     produces:
         *       - application/json
         *     responses:
         *       "200":
         *         description: "Success"
         *         schema:
         *           type: object
         *           properties:
         *             appName:
         *               type: string
         *               description: "Name of the app"
         *               example: "generic-ms"
         *             rss:
         *               type: number
         *               description: "Current memory usage"
         *               example: 82784256
         *             heapTotal:
         *               type: number
         *               description: "Total heap"
         *               example: 47484928
         *             heapUsed:
         *               type: number
         *               description: "Amount of heap in use"
         *               example: 45349336
         *             nrOfRequestsInProgress:
         *               type: number
         *               description: "Number of requests in progress to the app"
         *               example: 0
         *       "500":
         *         description: "A shutdown request is in progress"
         *         schema:
         *           type: object
         *           properties:
         *             message:
         *               type: string
         *               description: "Shutdown description"
         *               example: "Shutting down"
         */
        app.use('/alive', this.handleAlive.bind(this));

        // validate jwt before processing microservice functions
        if (this.options.jwtAuthEnabled) {
            app.use(validateJwt(this.options));
        }

        // register routes, to be added to router
        // then we will attach router to the app
        this.registerRoutes();
        app.use(this.defaultRoute, router);
        this.registerErrorRoutes(app);
    }

    /**
     * Setup the final error handling routes.
     * @param app
     */
    registerErrorRoutes(app) {
        // setup error handling. This needs to be at the bottom of
        // the chain. It also needs to have 4 parameters.
        app.use((err, req, res, next) => {
            let returnData = {error: err.message || 'Unexpected error'};
            if (err.name === 'RequestError' || err.name === 'StatusCodeError') {
                const {options = {}} = err;
                // show sanitized details, show stack, but not body.
                log.warn(`Request[${req.id}]: ${err.name}: msg: ${err.message}, status: ${err.statusCode}, method: ${options.method}, uri: ${options.uri}`, err.stack, {});
            } else if (err && err.stack) {
                // record error with stack info
                log.warn(`Request[${req.id}]: Express error handling: ${print(returnData)}, method: ${req.method}, uri: ${req.originalUrl}`, err, {});
            } else {
                // record error without stack info
                log.warn(`Request[${req.id}]: Express error handling: ${print(returnData)}, method: ${req.method}, uri: ${req.originalUrl}, err=${print(err)}`, {});
            }
            // Return message, we expect here err to be an exception
            // with message field plain text.
            res.status(500).json(returnData);
        });

        // If no route found by now, it's 404 error
        app.use('*', (req, resp) => {
            // Map other paths to 404
            log.info(`Request[${req.id}]: ${req.method} ${req.originalUrl} route not found`);
            let errorFile = path.join(__dirname, "../public/404.html");
            resp.status(404).sendFile(errorFile);
        });
    }

    /**
     * Helper method to provide a sanitized request body.
     * Override it if you want to hide information in the logs.
     * @param {Request} req
     * @returns {String} sanitized body
     */
    sanitizeInputBody(req) {
        return JSON.stringify(req.body || {});
    }

    /**
     * Override to sanitize url for logging if url contains sensitive information.
     * By default it uses req.originalUrl which contains the query string.
     * @param {Request} req
     * @returns {String} sanitized url
     */
    sanitizeUrl(req) {
        return req.originalUrl;
    }

    /**
     * Log a request
     * @param {Request} req The incoming request object, from express.js
     * @param {Response} res The response object, from express.js
     * @param {String} msg The message to log
     * @param {String[]} [tags] (optional) List of 'key:value' tags, to add at end of message.
     * @param {number|null} [elapsedTime] (optional) elapsed time
     */
    logRequest(req, res, msg, tags, elapsedTime) {
        const log = this.log,
            cookies = req.cookies || {},
            headers = req.headers || {},
            clientIp = headers['x-forwarded-for'] || req.connection.remoteAddress,
            sessionId = cookies.JSESSIONID || headers['x-session-id'],
            partnerTla = headers['x-partner-tla'] || headers['x-api-token-sub'] || req.issuer,
            cloudflareHeaders = ['cf-ray', 'cf-ipcountry', 'cf-connecting-ip'];
        // create an object with the header values if found.
        const cf = cloudflareHeaders.reduce((ac, current) => {
            const v = headers[current];
            if (v) {
                ac[current] = v;
            }
            return ac;
        }, {});
        const meta = {
                requestId: req.id,
                ...(sessionId ? {sessionId} : {}),
                host: headers.host || 'NA',
                clientIp: clientIp,
                ...(partnerTla ? {partnerTla} : {}),
                // Record Cloudflare headers if present
                ...(Object.keys(cf).length !== 0 ? cf : {}),
                // record elapsedTime as ES field
                ...(elapsedTime ? {elapsedTime} : {})
            };
        // Tags contain sanitized information we send to influxdb
        // We had to sanitize in order to limit cardinality of the values
        // as influxdb keeps them in memory
        // However for the logs it's best to record the original value of the URI.
        const uri= this.sanitizeUrl(req);
        const tagsToLog = Array.isArray(tags)
            ? tags.filter(name => !name.startsWith('uri:') && !name.startsWith('method:'))
            : [];
        const comma = tagsToLog.length ? ', ': '';
        const tagMsg = `method: ${req.method}, uri: ${uri}${comma}${tagsToLog.join(', ')}`;
        log.info(`Request ${msg}, ${tagMsg}`, meta);
    }

    /**
     * Audit request stop. Note that /alive is shown only in debug mode.
     * This is to limit the size of the log
     * @param {Request} req The incoming request object, from express.js
     * @param {Response} res The response object, from express.js
     */
    auditRequestStart(req, res) {
        const log = this.log,
            debug = log.isDebugEnabled();
        this.logRequest(req, res, 'start');
        if (debug) {
            // Note, req.cookies is not set, unless a cookie parser middleware is used.
            log.debug(`${req.method} ${req.url}, headers: ${print(req.headers)}`);
        }
        // count active request by this service
        // this.statsdClient.increment('active_rq', 1, ['method:' + req.method, 'uri:' + req.originalUrl]);
    }

    /**
     * Audit request end
     * @param {Request} req The incoming request object, from express.js
     * @param {Response} res The response object, from express.js
     * @param  {int}  elapsedTime
     */
    auditRequestEnd(req, res, elapsedTime) {
        let tags = this.auditRequestTags(req, res);
        this.logRequest(req, res, 'end', tags, elapsedTime);
        // measure elapsed time, tagging also by url and method
        // Note sometimes elapsed is zero, if the operation is very fast.
        // this.statsdClient.timing('rs_time', elapsedTime || 1, tags);
    }

    /**
     * Generate the audit request tags.
     * @param {Request} req
     * @param {Response}  res
     * @return {Array} An array of statsd tags, where each entry is in the form 'key:value'
     */
    auditRequestTags(req, res) {
        let headers = req.headers,
            partnerTla = headers['x-partner-tla'] || headers['x-api-token-sub'] || req.issuer,
            hasError = res.statusCode < 200 || res.statusCode > 299,
            tags = ['method:' + req.method, 'status:' + res.statusCode];

        const urlParsed = u.parse(req.originalUrl);
        // record simplified URL in the tags, to keep cardinality down
        // for errors, keep the high cardinality for alert/debugging purposes
        let uri = req.route && req.route.path ? req.route.path.replace(':', '_') : urlParsed.pathname;
        if (hasError) {
            uri = urlParsed.pathname
        }
        tags.push('uri:' + uri);

        if (partnerTla) {
            tags.push('partnerTla:' + partnerTla);
        }

        return tags;
    }

    /**
     * Method to add start/end tracking for each request.
     * It also add a tracking id using uuid to each request
     * Audit input parameters also, with option clearing of data.
     * @param  {Request}   req
     * @param  {Response}  res
     * @param  {Function}      next
     * @return void
     */
    trackRequests(req, res, next) {
        const debug = this.log.isDebugEnabled(),
            headers = req.headers || {};

        // setup simple access logging
        this.nrOfRequestsInProgress++;

        // Use the request-id from nginx if present
        // otherwise generate it using uuid.
        req.id = headers['x-request-id'] || uuid.v4();

        // track request start
        req.startAt = Date.now();
        req.log = new LogExpress(this.log, req);
        // filter out /alive unless debug mode
        if (!req.originalUrl.startsWith('/alive') || debug) {
            this.auditRequestStart(req, res);
            res.on('finish', () => {
                this.nrOfRequestsInProgress--;
                let elapsedTime = Date.now() - req.startAt;
                this.auditRequestEnd(req, res, elapsedTime);
            });
        } else {
            res.on('finish', () => {
                this.nrOfRequestsInProgress--;
            });
        }
        next();
    }

    /**
     * Sanitizes all body/query/param values.
     *
     * Depending on option value for --xss-sanitize this middleware
     * will react in the following ways:
     * "ERROR": call the default error handler by calling `next(err)`
     * effectively ending the request.
     * "IGNORE": a warning is logged during init and this middleware isn't used
     * "SANITIZE": (default if option not set) Sanitize the input value before it
     * reaches additional middleware.
     *
     * @param {Request} req The incoming request object, from express.js
     * @param {Response} res The response object, from express.js
     * @param next
     */
    // sanitizeAll(req, res, next) {
    //     const statsdClient = this.statsdClient,
    //         log = req.log,
    //         request = {
    //             body: req.body,
    //             query: req.query,
    //             params: req.params
    //         };
    //
    //     // /**
    //     //  * Helper to record xss sanitization telemetry
    //     //  * @param req The request object
    //     //  * @param {string} type - error or warning
    //     //  * @param {string} path - field path that was sanitized
    //     //  */
    //     // function recordXss(req, type, path) {
    //     //     const cookies = req.cookies || {},
    //     //         sessionId = cookies.JSESSIONID,
    //     //         referrer = req.headers.referrer;
    //     //
    //     //     let tags = [];
    //     //     if (sessionId) {
    //     //         tags.push(`session:${sessionId}`);
    //     //     }
    //     //     if (referrer) {
    //     //         tags.push(`referrer:${referrer}`);
    //     //     }
    //     //     tags.push('key:' + path);
    //     //     // statsdClient.increment(`xss_sanitization_${type}`, 1, tags);
    //     // }
    //
    //     try {
    //         iterator.forAll(request, (path, key, obj) => {
    //             const pathStr = `${path.join('.')}.${key}`,
    //                 value = obj[key];
    //
    //             if (typeof value === 'number' || typeof value === 'boolean') {
    //                 return; // can safely ignore numbers and booleans
    //             }
    //
    //             const sanitized = xssFilters.inHTMLData(value);
    //
    //             if (value !== sanitized) {
    //                 if (this.options.xssSanitize === 'ERROR') {
    //                     log.warn(`XSS Filter sanitized [${pathStr}]: ${value}. Sanitized value: ${sanitized}`);
    //                     // recordXss(req, 'error', pathStr);
    //                     throw new Error(`invalid request property "${pathStr}"`);
    //                 } else {
    //                     log.warn(`XSS Filter sanitized [${pathStr}]: ${obj[key]}. Sanitized value: ${sanitized}`);
    //                     // recordXss(req, 'warning', pathStr);
    //                     obj[key] = sanitized; // replace with sanitized value
    //                 }
    //             }
    //         });
    //     } catch (err) {
    //         next(err);
    //         return;
    //     }
    //     next();
    // }

    /**
     * Setup URL mapping. Override this to add new mappings.
     */
    registerRoutes() {
    }

    /**
     * Express middleware method to reject request if we have validation errors from express validators.
     *
     * @param {Request} req The incoming request object, from express.js
     * @param {Response} res The response object, from express.js
     * @param {Function} next Function to continue request chain
     * FIXME: Method should be static.
     */
    checkValidationResults(req, res, next) {
        const log = req.log,
            errors = validationResult(req);
        if (errors.isEmpty()) {
            next();
        } else {
            const mapped = errors.mapped();
            log.warn(`Request[${req.id}]: parameters did not pass validation ${print(mapped)}`);
            res.status(400).json(mapped);
        }
    }

    /**
     * Setup timers for the application. Override this method to add more.
     */
    initTimers() {
    }

    /**
     * Start listen on.
     */
    startExpress() {
        const app = this.app,
            log = this.log,
            options = this.options;

        let server = app;
        const sslEnabled = options.sslKey && options.sslCert;
        if (sslEnabled) {
            const sslOptions = {
                key: fs.readFileSync(options.sslKey),
                cert: fs.readFileSync(options.sslCert)
            };

            // if (!process.env.DISABLE_NODE_CUSTOM_CIPHERS) {
            //     sslOptions.maxVersion = 'TLSv1.2';
            //     sslOptions.minVersion = 'TLSv1.2';
            //     sslOptions.ciphers = tls.getCiphers().map(el=>el.toUpperCase()).filter(el=>el.startsWith('AES') && (el.endsWith('256') || el.endsWith('384'))).join(',');
            // }
            server = https.createServer(sslOptions, app);
        }

        app.server = server.listen(options.port, () => {
            log.info(`Running on ${sslEnabled ? "https" : "http"}://*:${options.port}/`);
        }).on('error', (e) => {
            log.error(`Could not start Express server, code: ${e.code}`, e, {});
            process.exit(1);
        });

        let timeout = options.serverSocketTimeout;
        if (timeout) {
            app.server.timeout = timeout * 1000;
        }
        log.info(`Server socket inactivity timeout is ${app.server.timeout / 1000} seconds for incoming connections.`);
    }

    static doCallbackOrPromise(p, callback) {
        if (!callback) {
            return p;
        }
        return p.then(result => callback(null, result))
            .catch(err => callback(err));
    }

    /**
     * Close the express app.
     * @param {Function<object, object>} callback A callback when complete, typically a 'done' function in unit tests.
     * If callback is not provided return promise.
     * FIXME: Convert to async method, and fix references
     * @return {Promise<void>}
     */
    close(callback) {
        const {log} = this;
        // express.close() is using callback, convert to promise
        this.app.server.closeAsync = Promise.promisify(this.app.server.close);
        //
        const _close = async () => {
            log.info('Shutting down express');
            await this.app.server.closeAsync();
            try {
                const oracleConnectionPool = this.oracledb && this.poolName ? this.oracledb.getPool(this.poolName) : null;
                if (oracleConnectionPool) {
                    log.info(`Closing Oracle Pool '${oracleConnectionPool.poolAlias}'`);
                    await oracleConnectionPool.close(10); // 10 second grace period
                    log.info(`Closed Oracle Pool '${oracleConnectionPool.poolAlias}'`);
                }
            } catch (e) {
                log.error('Unable to close Oracle Pool', e, {});
            }
            // if (this.closeStatsdClient) {
            //     await this.closeStatsdClient();
            // }
            if (this.snowflakeDbConnection) {
                try {
                    log.info(`Closing Snowflake connectionId: ${this.snowflakeDbConnection.getId()}`);
                    await this.snowflakeDbConnection.destroyPromise();
                    log.info(`Closed Snowflake connectionId: ${this.snowflakeDbConnection.getId()}`);
                } catch (e) {
                    log.error(`Unable to close Snowflake connectionId: ${this.snowflakeDbConnection.getId()}, error code: ${e.code}, message: ${e.message}`, e, {});
                }
            }
        };
        return ExpressApp.doCallbackOrPromise(_close(), callback);
    }
}

/**
 * If validation is successful, the request object will contain the payload of the jwt in a field called
 * validatedAuthJwtPayload to allow additional processing.
 * @param {Object} options
 * @param {Boolean} options.jwtAuthEnabled - if true, perform jwt validation, otherwise call next
 * @param {String} options.jwtKeyId - required to decode jwt
 * @param {String} options.jwtSecretKey - required to decode jwt
 * @param {String} options.jwtAlg - required to decode jwt, default HS256
 * @param {Number} options.jwtMaxTtl - required to validate jwt, default 300 (seconds)
 * @param {Boolean} options.validateJwt - control validator initialization via CMA
 * @returns {Function} - a middleware function that validates an authentication jwt from the request
 */
function validateJwt(options) {
    //Skip middleware initialization if validateJwt CMA is set to false.
    //No impact on initialization if validateJwt CMA is not defined or if
    //it is set to true
    if(options?.validateJwt === false){
        return (req, res, next) => {
            next();
        }
    }
    // prepare jwt util
    if (!options.jwtSecretKey) {
        throw new Error('options.jwtSecretKey is missing');
    }
    let jwtSecretKey = unwrap(options.jwtSecretKey);

    jwtSecretKey = Buffer.from(jwtSecretKey, 'base64').toString('utf-8');

    const jwtOptions = {
        algorithm: options.jwtAlg,
        secretKey: jwtSecretKey,
        kid: options.jwtKeyId
    };
    const jwtUtil = new JWTUtil(log, jwtOptions);
    const maxTtl = options.jwtMaxTtl;

    return (req, res, next) => {
        const {log} = req;
        const jwt = req.query.authJwt || req.headers['x-auth-jwt'] || req.query.JWT_TOKEN;
        if (!jwt) {
            log.error(`jwt not provided`);
            res.status(403).send('Forbidden');
            return;
        }

        try {
            // decode payload to do some validation
            // NOTE this code can be replaced with jwt-simple.decode(noVerify:true)
            const base64UrlPayload = jwt.split('.')[1],
                base64Payload = base64UrlPayload.replace('-', '+').replace('_', '/'),
                payload = JSON.parse(atob(base64Payload));

            const {iss} = payload;
            if (!iss) {
                log.error(`missing iss in jwt`);
                res.status(403).send('Forbidden');
                return;
            }

            const {iat, exp, requestedTTL} = payload;
            if (exp) {
                // we have expiration time.
                const currentTimeSeconds = Math.floor(Date.now() / 1000);
                if (currentTimeSeconds > exp) {
                    log.error(`jwt expired`);
                    res.status(403).send('Forbidden');
                    return;
                }
            } else if (iat) {
                // we have issued at time field.
                if (!requestedTTL) {
                    log.error(`missing requestedTTL in jwt`);
                    res.status(403).send('Forbidden');
                    return;
                }
                const currentTimeSeconds = Math.floor(Date.now() / 1000);
                const timeElapsedSeconds = currentTimeSeconds - iat;
                const ttlSeconds = Math.min(requestedTTL, maxTtl);
                if (requestedTTL > maxTtl) {
                    log.info(`requestedTTL is greater than max TTL, using max TTL: ${maxTtl}`);
                }
                if (timeElapsedSeconds > ttlSeconds) {
                    log.error(`jwt expired`);
                    res.status(403).send('Forbidden');
                    return;
                }
            } else {
                log.error(`missing iat/exp in jwt`);
                res.status(403).send('Forbidden');
                return;
            }
            // verify signature
            const result = jwtUtil.decode(jwt);
            if (!result) {
                log.error(`failed to decode jwt, result is null/undefined`);
                res.status(403).send('Forbidden');
                return;
            }
            req.validatedAuthJwtPayload = payload;
        } catch (err) {
            log.error(`failed to validate jwt`, err, {});
            res.status(403).send('Forbidden');
            return;
        }
        return next();
    }
}

/**
 * Helper function to add behaviour to a class.
 * @param {Class.prototype} target
 * @param {Object} behaviour - object with methods to add
 */
function mixinFunctions(target, behaviour) {
    let keys = Object.keys(behaviour);
    for (let property of keys) {
        Object.defineProperty(target, property, {value: behaviour[property], configurable: true});
    }
}

/**
 * Initialize resources asynchronously.
 * @param {Object} options The resolved start-up options.
 * @returns {Promise<Object>} Resolves to initialized context.
 */
async function initialize(options) {
    if (options && options.dbPoolMax > 4) {
        // If the Oracle DB connection pool max is larger than the default of 4 then we must increase the number
        // of threads available to nodejs.
        // Note that the following command only works on linux. On Windows, the environment property UV_THREADPOOL_SIZE
        // must be set before the app is executed.
        process.env.UV_THREADPOOL_SIZE = options.dbPoolMax;
    }

    let context = {
        options: options || {}
    };

    return await initLogging(context);
    // return await initVault(context);
}

/**
 * Decorate the context with an initialized logger.
 * @param context
 * @returns {Promise<Object>} Resolves to initialized context.
 */
async function initLogging(context) {
    const options = context.options || {};
    context.log = log.initLog(options);
    context.log.info('Options will mask fields name ending : Password,Secret,SecretKey,Key,Cert,pass,Token,Passphrase');
    context.log.info('Logging initialized, options: %s', JSON.stringify(options));
    // if (!options.exitOnError) {
    //     utils.logProcessErrors(context.log);
    // }
    return context;
}

/**






/**
 * Utility function force node.js module to be reloaded.
 * @param  {string} modulePath - module load path
 * @return {Object}            - reloaded module
 */
function requireReload(modulePath) {
    delete require.cache[require.resolve(modulePath)];
    return require(modulePath);
}

function addStandardOptions(cmd) {
    return cmd
        .option('--app-name <app-name>', 'Application name used in logs (default is node.js script name')
        
}

function addStandardJwtOptions(cmd) {
    return cmd
        .option('--jwt-auth-enabled <jwt-auth-enabled>', 'Enable jwt authentication for this microservice', false)
        .option('--jwt-key-id <key id>', 'JWT key id')
        .option('--jwt-secret-key <secret>', 'Base64-encoded and wrapped JWT secret key')
        .option('--jwt-alg <jwt-alg>', 'The algorithm for decoding the authentication jwt, default HS256', 'HS256')
        .option('--jwt-max-ttl <jwt-max-ttl>', 'Maximum TTL (time to live in seconds) for the authentication jwt, default 300', parseInteger, 300)
}

/**
 * Initialize default options with Commander
 * @param {Number} defaultPort - when set to zero, options are for job not an express micro service.
 * @returns {commander}
 * @see commander module
 */
function initDefaultOptions(defaultPort = 0) {
    //
    const program = new commander.Command(),
        //appName = path.basename(__filename),
        //logFile = `logs/${appName}/${appName}.log.<day>`,
        port = parseInt(process.env.TEST_PORT || 0) + defaultPort;
    const expressService = (defaultPort !== 0);
    if (expressService) {
        program.option('--port [port]', `Port number [${port}]`, intParser, `${port}`)
            .option('--xss-sanitize [reaction]', 'How to react to an occurrence of sanitization [ERROR|IGNORE|SANITIZE]', 'SANITIZE');
    }
    addStandardOptions(program);
    addStandardJwtOptions(program);
    program.usage('[options]');
    return addStandardDbOptions(program);
}

function addStandardDbOptions(cmd) {
    return cmd
}







/**
 * Simple int parser to use with numeric arguments. Required
 * to handle commander behaviour where it send the default/current value
 * as second parameter. However parseInt() second parameter is base of the number to parse.
 * @param  {string} val command line parameter
 * @return {int}
 */
function intParser(val) {
    return parseInt(val);
}

/**
 * Allow use of number ranges on command line
 * @param  {string} val
 * @return {array}
 */
function rangeParser(val) {
    return val.split('..').map(Number);
}




/**
 * Function to add access control headers if allowed-origin-domains parameter is passed
 *
 * @param req
 * @param res
 * @param next
 */
async function addAccessControlOriginHeader(req, res, next){
    res.header('Access-Control-Allow-Origin', '*');

    // const allowedOriginDomains = this.options.allowedOriginDomains;
    // if (allowedOriginDomains){
    //     const allowedDomains = allowedOriginDomains.split(","),
    //         origin = req.get('origin') || '',
    //         endsWith = (allowedDomain) => origin.endsWith(allowedDomain),
    //         isDomainAllowed = allowedDomains.some(endsWith);
    //     if (isDomainAllowed) {
    //         res.header('Access-Control-Allow-Origin', '*');
    //     }
    // }
    next();
}

function allowCrossDomain(req, res, next) {
    res.header("Access-Control-Allow-Origin", "*")
    res.header(
        "Access-Control-Allow-Headers",
        "Origin, X-Requested-With, Content-Type, Accept, Authorization,idtoken"
    );
    if (req.method === 'OPTIONS') {
        res.header('Access-Control-Allow-Methods', 'PUT, POST, PATCH, DELETE, GET');
        return res.status(200).json({});
    }
    next();
}



/**
 * Generate an init function based by providing the list of mandatory fields.
 * @param {...String} mandatoryFields
 * @returns {Function} - function that can be plugged in the init chain.
 */
function initValidateOptions(...mandatoryFields) {
    return (context) => {
        const options = context.options || {};
        let missingFields = mandatoryFields.filter(fieldName => !options[fieldName]);
        if (missingFields.length > 0) {
            return Promise.reject('Command line options missing: ' + missingFields.join(', '));
        }
        return context;
    };
}


/**
 * Helper middleware for Express to make sure we catch all errors when handling an express request. Wrap the calling
 * function with this and you don't need to use try/catch on each request. This function will catch all exceptions and
 * pass it to the default error handler. For more specific error handling you can create an error handling function and
 * add it to the routes you create for your own service. See http://expressjs.com/en/guide/error-handling.html
 */
const asyncMiddleware = fn =>
    (req, res, next) => {
        Promise.resolve(fn(req, res, next))
            .catch((err) => {
                req.log.error('An error has occurred', err);
                next(err);
            });
    };

const parseList = (str => (str || '').split(','));
const parseInteger = (str => parseInt(str, 10));

// the original implementation of parseIntParam was done incorrectly
// we now changed parseIntParam to do the same thing as parseInteger
// and at the same time keep the exports the same to avoid breaking existing
// code that calls parseIntParam
const parseIntParam = parseInteger;


const parseBooleanParam = str => {
    if (!str) {
        return false
    }
    str = str.toLowerCase()
    return str === 'true' || str === 'yes'
}

/**
 * Generate a function that will parse out options fields.
 * @param {Object} optionParsers - object matching names to parse out
 * @returns {*}
 */
function parseOptionFields(optionParsers) {
    return (context) => {
        const options = context.options || {};
        for (let fieldName of Object.keys(optionParsers)) {
            const value = options[fieldName],
                parser = optionParsers[fieldName];
            options[fieldName] = parser(value);
        }
        return context;
    };
}

module.exports = {
    ExpressApp,
    LogExpress,
    TimeLogger,
    initDefaultOptions,
    addStandardOptions,
    initialize,
    initLogging,
    intParser,
    rangeParser,
    mixinFunctions,
    requireReload,
    addAccessControlOriginHeader,
    parseBooleanParam,
    parseIntParam,
    initValidateOptions,
    asyncMiddleware,
    parseList,
    parseInteger,
    allowCrossDomain,
    addStandardDbOptions,
    parseOptionFields,
    validateJwt,
};
