const mongodb = require('mongodb'),
    {MongoClient, ReadPreference} = mongodb,
    {readFileSync} = require('fs');
    // {formatBool, parseInteger} = require('./utils'),
    // {unwrapIfNeeded} = require('./crypt-utils');


function appendMongoDbOptions(options) {
    // Note that we have no default for these. They are mandatory parameters
    // that need to provided in command line, or in Vault overrides.
    return options.option('--mongo-url <mongo-url>', 'MongoDb URL')
        .option('--mongo-user <mongo-user>', 'MongoDb auth.user')
        .option('--mongo-password <mongo-password>', 'MongoDb auth.password')
        .option('--mongo-ssl-enabled <enabled>', 'Connect to MongoDb using SSL', false)
        .option('--mongo-retry-writes-enabled <enabled>', 'Connect to MongoDb with retryWrites, to retry during a topology change or temporary network error', true)
        .option('--mongo-noauth <mongo-noauth>', 'MongoDb noauth flag', false)
        .option('--mongo-connect-timeout-ms <mongo-connect-timeout>', 'MongoDb client connect timeout (default 10000)', 10000)
        .option('--mongo-min-pool-size <mongo-min-pool-size>', 'MongoDb min pool size (default: 0)', 0)
        .option('--mongo-max-pool-size <mongo-max-pool-size>', 'MongoDb max pool size (default: 10)', 10)
        .option('--mongo-direct-connection <mongo-direct-connection>', 'Allow a driver to force a Single topology type with a connection string containing one host', false)
        .option('--mongo-write-concern-w <mongo-write-concern-w>', 'MongoDB WriteConcern acknowledgement by number of nodes, or simply \'majority\'', 1)
        .option('--mongo-write-concern-j <mongo-write-concern-j>', 'MongoDB WriteConcern acknowledgement that the write op was written to the journal', false)
        .option('--mongo-read-preference <mongo-read-preference>', 'MongoDB ReadPreference for all find / aggregate requests. See same option on find/aggregate queries for more granularity. (default: primary) [primary, primaryPreferred, secondary, secondaryPreferred, nearest]', 'primary')
        .option('--client-cert <path>', 'Client certificate path');
}

/**
 * Initialize mongodb client resource.
 * MongoClient options, see: https://mongodb.github.io/node-mongodb-native/3.6/api/MongoClient.html
 * @param context
 * @returns {Promise<*>}
 */
async function initMongoClient(context) {
    const {log, options} = context;
    let {
        mongoUrl, mongoMinPoolSize, mongoMaxPoolSize, mongoConnectTimeoutMs,
        mongoWriteConcernW, mongoWriteConcernJ, mongoReadPreference, mongoDirectConnection
    } = options;
    let connectOpts = {
        directConnection: mongoDirectConnection,
        auth: options.mongoNoauth ? null : {
            username: options.mongoUser,
            // password: unwrapIfNeeded(options.mongoPassword)
            password: options.mongoPassword
        },
        connectTimeoutMS: mongoConnectTimeoutMs,
        // keepAlive: true,
        writeConcern: {
            w: (mongoWriteConcernW === 'majority') ? mongoWriteConcernW : parseInt(mongoWriteConcernW),
            j: mongoWriteConcernJ
        },
        ...(mongoReadPreference ? {readPreference: mongoReadPreference} : {}),
        minPoolSize: mongoMinPoolSize,
        maxPoolSize: mongoMaxPoolSize
    };

    if (!mongoUrl) {
        throw new Error("MongoDB url is missing");
    }
    if (!options.mongoNoauth && (!options.mongoUser || !options.mongoPassword)) {
        throw new Error("MongoDB userName or password are missing");
    }

    if (options.mongoSslEnabled) {
        // Enable SSL connection, validate certificate chain against environment's CA, & accept any server hostname.
        mongoUrl += (mongoUrl.indexOf("?") > 0 ? "&" : "?") + "ssl=true";
        connectOpts["sslValidate"] = true;

        if (options.clientCert) {
            connectOpts["sslKey"] = options.clientCert;
            connectOpts["sslCert"] = options.clientCert;
        }
    }

    if (mongoUrl.indexOf("retryWrites=") < 0) {
        mongoUrl += (mongoUrl.indexOf("?") > 0 ? "&" : "?") + "retryWrites=" + (options.mongoRetryWritesEnabled || false).toString();
    }

    log.info('Connecting Mongodb client, url: %s', mongoUrl);
    const mongoClient = await MongoClient.connect(mongoUrl, connectOpts);

    // Use a single reference to the mongo DB.
    context.db = mongoClient.db();
    context.mongoClient = mongoClient;
    log.info('Mongodb client connected %s', options.mongoSslEnabled ? '(SSL)' : '');
    return context;
}

// https://www.mongodb.com/docs/manual/core/read-preference/
const readFromPrimaryPreferred = {readPreference: ReadPreference.PRIMARY_PREFERRED};
const readFromSecondaryPreferred = {readPreference: ReadPreference.SECONDARY_PREFERRED};
// https://www.mongodb.com/docs/manual/reference/write-concern/
const writeToMajority = {writeConcern: {w: 'majority'}}


module.exports = {
    appendMongoDbOptions,
    initMongoClient,
    readFromPrimaryPreferred,
    readFromSecondaryPreferred,
    writeToMajority
};
