const AWS = require('aws-sdk'),
    {encrypt, unwrap, unwrapIfNeeded} = require('./crypt-utils'),
    multer = require("multer"),
    moment = require('moment');
    // {codeToTla, sendHttpRequestAsync, sendJsonRequestAsync} = require('./utils'),
    // {formatMessage} = require('./string-utils');

const appendS3Options = (options) => {
    return options.option('--s3-access-key <secret>', 'S3 access key')
        .option('--s3-secret-key <secret>', 'S3 secret key')
        .option('--s3-crypt-key <secret>', 'S3 crypt key')
        .option('--s3-bucket <name>', 'S3 bucket')
        .option('--s3-region <name>', 'S3 region')
        .option('--s3-url <url>', 'S3 endpoint URL')
        .option('--s3-timeout <timeout>', 'S3 endpoint URL', 120000); // same default as createS3Client below
};

const initS3Client = async (context) => {
    const options = context.options || {};
    context.s3Client = createS3Client(options);
    return context;
};


/**
 * upload file with multer
 * @param context
 * @returns {Promise<{options}>}
 */
function uploadFile(maxSize){
    return multer({
        storage: multer.memoryStorage(),
        limits: {
            fileSize: maxSize
        },
        fileFilter(req, file, cb){
            if(!file.originalname) {
                return cb(new Error('File name is required'))
            } else if(file.originalname && !file.originalname.toLowerCase().match(/\.(jpeg|jpg|png)$/)){
                return cb(new Error('Only image files are supported for uploads'))
            }
            cb(undefined, true)
        }
    });
}


/**
 * Init s3 templateLoader client
 * @param context
 * @returns {Promise<{options}>}
 */
async function initS3TemplateLoaderClient(context) {
    const options = context.options || {};
    if(!options.templateLoaderBucketAccessKey || !options.templateLoaderBucketSecretKey){
        context.log.info(`Skipping templateLoader Init`);
        return context;
    }
    AWS.config.setPromisesDependency(require('bluebird'));

    context.options.templateLoaderBucketClient = new AWS.S3({
        accessKeyId: unwrap(options.templateLoaderBucketAccessKey),
        secretAccessKey: unwrap(options.templateLoaderBucketSecretKey),
        region: options.templateLoaderBucketRegion
    });
    return context;
}


function createS3Client(options){
    const s3Options = {
        accessKeyId: unwrapIfNeeded(options.s3AccessKey),
        secretAccessKey: unwrap(options.s3SecretKey),
        s3ForcePathStyle: true, // needed with Minio
        signatureVersion: 'v4',
        httpOptions: {timeout: options.s3Timeout || 120000, connectTimeout: 120000}
    };


    if (options.s3Url != null) {
        s3Options.endpoint = options.s3Url;
    } else {
        s3Options.region = options.s3Region;
    }
    console.log("s3 option shere", s3Options)

    return new AWS.S3(s3Options);
}

/**
 * list up to 1000 object keys with prefix within a bucket, returned in lexicographically ascending order
 * number of objects beyond 1000 can be achieved with ContinuationToken. Note this functionality is no implemented so we
 * are limited to the first 1000 results for now
 * see https://docs.aws.amazon.com/AWSJavaScriptSDK/latest/AWS/S3.html#listObjectsV2-property
 *
 * @param options : {
 *     s3Bucket,
 *     s3OjectKeyPrefix
 * }
 * @param prefix
 * @param s3Client
 * @param log
 * @return {Promise<*>}
 */
const listObjectKeys = async (options, s3Client, log) => {
    const { s3Bucket, s3OjectKeyPrefix } = options;
    let params = {
        Bucket: s3Bucket,
        Prefix: s3OjectKeyPrefix
    };
    log.info(`Trying to listObjects: ${s3Bucket}/${s3OjectKeyPrefix}`);
    try {
        const data = await s3Client.listObjectsV2(params).promise();
        if (data.Contents && data.Contents.length > 0) {
            let keys = data.Contents.map(c => c.Key);
            log.info(`listObjects data: ${keys}`);
            return keys;
        } else {
            log.warn(`listObjects not found: ${s3Bucket}/${s3OjectKeyPrefix}`);
            return null;
        }
    } catch (err) {
        log.error(`Failed to listObjects: ${s3Bucket}/${s3OjectKeyPrefix}`, err, {});
        return null;
    }
};

/**
 * Upload an empty object to S3.
 * Common use case: uploading an empty control file.
 *
 * @param s3Bucket
 * @param s3Key
 * @param s3Client
 * @return {Promise<*>}
 */
async function uploadEmptyObject(s3Bucket, s3Key, s3Client) {
    const params = {
        Bucket: s3Bucket,
        Key: s3Key,
        Body: ''
    };
    return s3Client.putObject(params).promise();
}

/**
 * common query function shared by all query methods
 * queryParamsOverwrite parameter allow you to fully control the query parameters for S3 selectObjectContent()
 * by overriding any query parameter keys,
 * see https://docs.aws.amazon.com/AWSJavaScriptSDK/latest/AWS/S3.html#selectObjectContent-property
 *
 * @param options : {
 *     s3Bucket,
 *     s3Key
 * }
 * @param s3Client
 * @param log
 * @param queryParamsOverwrite
 * @return {Promise<null>}
 */
const executeQuery = async (options, s3Client, log, queryParamsOverwrite) => {
    const { s3Bucket, s3Key } = options;
    const queryParams = Object.assign({
        Bucket: s3Bucket,
        Key: s3Key,
        ExpressionType: 'SQL',
        Expression: `SELECT * FROM S3Object`,
        InputSerialization: {
            CSV: {
                RecordDelimiter: '\n',
                FieldDelimiter: ',',
                FileHeaderInfo: 'NONE',
            }
        },
        OutputSerialization: {
            JSON: {}
        }
    }, queryParamsOverwrite);

    log.info(`Trying to selectObjectContent: ${s3Bucket}/${s3Key}`);
    try {
        const data = await s3Client.selectObjectContent(queryParams).promise();
        // data.Payload is a Readable Stream
        const stream = data.Payload;

        let streamPromise = new Promise(function (resolve, reject) {
            let result = null;
            // Read events as they are available
            stream.on('data', (event) => {
                if (event.Records) {
                    // event.Records.Payload is a buffer containing
                    // a single record, partial records, or multiple records
                    result = event.Records.Payload.toString('utf-8');
                } else if (event.Stats) {
                    log.info(`Processed ${event.Stats.Details.BytesProcessed} bytes`);
                } else if (event.End) {
                    log.info('SelectObjectContent completed');
                }
            });
            stream.on('error', (err) => {
                log.error(`Failed to selectObjectContent: ${s3Bucket}/${s3Key}`, err, {});
                reject(err);
            });
            stream.on('end', () => {
                log.info(`selectObjectContent data: ${result}`);
                resolve(result);
            });
        });
        return await streamPromise;
    } catch (err) {
        log.error(`Failed to selectObjectContent: ${s3Bucket}/${s3Key}`, err, {});
        return null;
    }
};

/**
 * query s3 key/path resource with CSV content for start with string matching
 * returns boolean as match has been found or not found
 *
 * @param options : {
 *     s3Bucket,
 *     s3Key,
 *     partialIdentifier,
 *     column
 * }
 * @param s3Client
 * @param log
 * @return {Promise<null>}
 */
const queryStartsWithS3Content = async (options, s3Client, log) => {
    const queryParams = {
        Bucket: options.s3Bucket,
        Key: options.s3Key,
        ExpressionType: 'SQL',
        Expression: `SELECT ${options.column} FROM S3Object WHERE ${options.column} like '${options.partialIdentifier}%'`,
        InputSerialization: {
            CSV: {
                FieldDelimiter: ',',
                RecordDelimiter: '\n',
                FileHeaderInfo: 'NONE',
            }
        },
        OutputSerialization: {
            JSON: {}
        }
    };

    return await executeQuery(options, s3Client, log, queryParams);
};

/**
 * query s3 key/path resource with CSV content for partial string matching
 * returns boolean as match has been found or not found
 *
 * @param options : {
 *     s3Bucket,
 *     s3Key,
 *     expression
 * }
 * @param s3Client
 * @param log
 * @return {Promise<null>}
 */
const querySearchS3Content = async (options, s3Client, log) => {
    const {s3Bucket, s3Key, columns, expression} = options;

    const queryParams = {
        Bucket: s3Bucket,
        Key: s3Key,
        ExpressionType: 'SQL',
        Expression: expression || `SELECT ${columns} FROM S3Object`,
        InputSerialization: {
            CSV: {
                RecordDelimiter: '\n',
                FieldDelimiter: ',',
                FileHeaderInfo: 'NONE',
            }
        },
        OutputSerialization: {
            JSON: {}
        }
    };
    return await executeQuery(options, s3Client, log, queryParams);
};

/**
 * Add this method to use 'region' instead of endpoint
 * @param context
 * @returns {Promise<{options}>}
 */
async function initS3ClientRegion(context) {
    const options = context.options || {};

    context.s3Client = new AWS.S3({
        accessKeyId: unwrap(options.s3AccessKey),
        secretAccessKey: unwrap(options.s3SecretKey),
        region: options.s3Region
    });
    return context;
}


/**
 * Log the remote calls to S3. Pass in the s3Key as a parameter to determine the save path
 *
 * @param log
 * @param s3Config
 * @param s3Key
 * @param header
 * @param url
 * @param httpOptions
 * @param rsObj
 * @param duration
 * @returns {Promise<void>}
 */
async function s3LogTrailUpload(log, s3Config, s3Key, header, url, httpOptions, rsObj, duration) {

    if(s3Config == null){
        log.info("S3 Configs not defined for log trail.");
        return;
    }

    if(s3Config.s3Client == null || !(s3Config.s3Client instanceof AWS.S3)){
        log.info("S3 Client not defined for log trail.");
        return;
    }

    if(s3Config.s3CryptKey == null || !(typeof s3Config.s3CryptKey === 'string' )){
        log.info("S3 crypt key is not a string");
        return;
    }

    // Handling masked response data to s3
    let responseData = rsObj?.maskedResponse ? rsObj.maskedResponse : rsObj.data;
    if (typeof responseData === 'object' && responseData !== null) {
        responseData = JSON.stringify(responseData);
    }

    let logTrailObj = {
        req_url: url,
        req_body: httpOptions.data || httpOptions.body,
        req_headers: httpOptions.headers,
        req_time: moment().valueOf(), // gets NOW in epoch time
        channel_code: header.channelCode,
        application_name: header.applicationCode,
        session_id:"",
        resp_time: duration,
        resp_code: rsObj.statusCode,
        resp_headers: rsObj.Headers,
        resp_body: responseData
    }

    // Encrypt RT logtrail payload
    let unwrappedKey = unwrap(s3Config.s3CryptKey);
    let encryptedLogTrail =  encrypt(JSON.stringify(logTrailObj), unwrappedKey);

    const params = {
        Bucket: s3Config.s3Bucket,
        Key: s3Key,
        Body: encryptedLogTrail
    };

    // Upload to s3
    try {
        log.info("Uploading to S3 with s3Key: " + s3Key);
        await s3Config.s3Client.putObject(params).promise();
    } catch (err) {
        log.error(`Error when attempting to save object to S3://${params.Bucket}/${params.Key}, data: ${params.Body}`, err, {});
        throw new Error(`There was an error when attempting to save an object for clientCode=${header.client}, key=${params.Key}`);
    }
}

/**
 * Create s3 key for rt_cif logtrail
 * @param header
 * @param rsCode
 * @returns {string|*}
 */
function getRtCifS3LogTrailKey(header, rsCode){
    let now = moment();
    if(!rsCode) {
        rsCode = 'UNKNOWN';
    }
    // moment returns months from 0 - 11
    let month = now.get('month') + 1;
    let accountNumber = encodeStringForS3(header.accountNumber);
    return formatMessage('rt_cif/{0}/{1}-{2}-{3}_{4}_{5}_{6}-{7}-{8}-{9}_{10}.json',
        codeToTla(header.client).toUpperCase(),
        now.get('year'),
        month.toString().padStart( 2, '0'),
        now.get('date').toString().padStart( 2, '0'),
        accountNumber,
        header.customerSegment || 'CONSUMER',
        now.get('hour').toString().padStart( 2, '0'),
        now.get('minute').toString().padStart( 2, '0'),
        now.get('second').toString().padStart( 2, '0'),
        now.get('ms').toString().padStart( 3, '0'),
        rsCode);
}

/**
 * Create s3 key for rt_post logtrail
 * @param header
 * @param rsCode
 * @returns {string|*}
 */
function getRtPostS3LogTrailKey(header, rsCode){
    let now = moment();
    if(!rsCode) {
        rsCode = 'UNKNOWN';
    }
    // moment returns months from 0 - 11
    let month = now.get('month') + 1;
    let accountNumber = encodeStringForS3(header.accountNumber);
    return formatMessage('rt_post/{0}/{1}-{2}-{3}_{4}_{5}_{6}_{7}-{8}-{9}-{10}_{11}.json',
        codeToTla(header.client).toUpperCase(),
        now.get('year'),
        month.toString().padStart( 2, '0'),
        now.get('date').toString().padStart( 2, '0'),
        accountNumber,
        header.customerSegment,
        header.paymentRefNum,
        now.get('hour').toString().padStart( 2, '0'),
        now.get('minute').toString().padStart( 2, '0'),
        now.get('second').toString().padStart( 2, '0'),
        now.get('ms').toString().padStart( 3, '0'),
        rsCode);
}

/**
 * Encode all non-alphanumeric characters to avoid unexpected behavior in S3.
 * @param string
 * @returns encoded {accountNumber}
 */
function encodeStringForS3(string){
    return string ? string.replace(/[^A-Za-z0-9]/g, c => '.' + c.charCodeAt() + '.') : null;
}
/**
 * Use this in RT CIF microservices, to log all calls to logtrail.
 * @param url
 * @param options
 * @param header
 * @param s3Config
 * @returns {Promise<void>}
 */
async function sendHttpRequestCifAsync(url, options, header, s3Config, log, transform) {

    let duration = 0;
    let rsObj = {statusCode:500, data: "", Headers:""};

    try {
        let startTime = moment();
        rsObj = await sendHttpRequestAsync(url, options);

        // Masking sensitive fields from response based on inputs passed from template
        if (transform?.template?.maskedFields &&
            Array.isArray(transform?.template?.maskedFields) &&
            transform?.template?.maskedFields.length > 0 &&
            transform?.maskBodyByElement && typeof transform.maskBodyByElement === 'function') {
            rsObj = transform.maskBodyByElement(rsObj, transform.template.maskedFields, transform.extDataAndConfig);
        }
        duration = moment() - startTime;

    } catch(e){
        log.warn(`Request failed. URL: ${url}`);
        if(e.code){
            rsObj.statusCode = e.code;
            rsObj.data = e.error;
            rsObj.hasTimedOut = e.hasTimedOut;
            log.warn(`Request failure reason - error code ${e.code}.`);
        } else if(typeof e.message === 'string' && e.message.match(/Invalid URL/g)){
            log.warn(`Request failure reason - ${e.message}`);
        } else {
            log.warn(`Request failure reason - UNKNOWN`);
        }

    } finally {
        let s3Key = getRtCifS3LogTrailKey(header, rsObj.statusCode);
        s3LogTrailUpload(log, s3Config, s3Key, header, url, options, rsObj, duration);
    }

    return rsObj;
};

/**
 * Use this in RT CIF microservices, to log all calls to logtrail.
 * @param url
 * @param options
 * @param header
 * @param s3Config
 * @returns {Promise<void>}
 */
async function sendJsonRequestCifAsync(url, options, header, s3Config, log) {

    let duration = 0;
    let rsObj = {statusCode:"", data: "", Headers:""};

    try {
        let startTime = moment();
        rsObj = await sendJsonRequestAsync(url, options);
        duration = startTime - moment();

    } catch(e){
        if(e.code){
            rsObj.statusCode = e.code;
        }

    } finally {
        let s3Key = getRtCifS3LogTrailKey(header, rsObj.statusCode);
        s3LogTrailUpload(log, s3Config, s3Key, header, url, options, rsObj, duration);
    }

    return rsObj;
};

/**
 * Use this in RT Post microservices, to log all calls to logtrail.
 * @param url
 * @param options
 * @param header
 * @param s3Config
 * @returns {Promise<void>}
 */
async function sendHttpRequestPostAsync(url, options, header, s3Config, log) {

    let duration = 0;
    let rsObj = {statusCode:500, data: "", Headers:""};

    try {
        let startTime = moment();
        rsObj = await sendHttpRequestAsync(url, options);
        duration = startTime - moment();

    } catch(e){
        log.warn(`Request failed. URL: ${url}`);
        if(e.code){
            rsObj.statusCode = e.code;
            rsObj.data = e.error;
            rsObj.hasTimedOut = e.hasTimedOut
            log.warn(`Request failure reason - error code ${e.code}.`);
        } else if(typeof e.message === 'string' && e.message.match(/Invalid URL/g)){
            log.warn(`Request failure reason - ${e.message}`);
        } else {
            log.warn(`Request failure reason - UNKNOWN`);
        }

    } finally {
        let s3Key = getRtPostS3LogTrailKey(header, rsObj.statusCode);
        s3LogTrailUpload(log, s3Config, s3Key, header, url, options, rsObj, duration);
    }

    return rsObj;
};

/**
 * Use this in RT Post microservices, to log all calls to logtrail.
 * @param url
 * @param options
 * @param header
 * @param s3Config
 * @returns {Promise<void>}
 */
async function sendJsonRequestPostAsync(url, options, header, s3Config, log) {

    let duration = 0;
    let rsObj = {statusCode:"", data: "", Headers:""};

    try {
        let startTime = moment();
        rsObj = await sendJsonRequestAsync(url, options);
        duration = startTime - moment();

    } catch(e){
        if(e.code){
            rsObj.statusCode = e.code;
        }

    } finally {
        let s3Key = getRtPostS3LogTrailKey(header, rsObj.statusCode);
        s3LogTrailUpload(log, s3Config, s3Key, header, url, options, rsObj, duration);
    }

    return rsObj;
};



/**
 * This function retrieves an object from s3.
 * @param options
 * @param key
 * @param s3
 * @param log
 * @returns obj or null
 */
const getJSONObjectAsync = async (options, key, s3, log) => {
    const {bucket} = options;
    let params = {
        Bucket: bucket,
        Key: key
    }
    log.info(`Trying to getObject: ${bucket}/${key}`);
    try {
        const data = await s3.getObject(params).promise();
        let obj = data.Body.toString('utf-8')

        if(options.objectType === "html") {
            obj = obj.replace(/\n|\r|\t/g, "");
        } else {
            obj = JSON.parse(obj);
        }
        //log.info(`getObject data: ${JSON.stringify(obj)}`);
        return obj;
    } catch (err) {
        log.error(`Failed to getObject: ${bucket}/${key}`, err, {});
        return null;
    }
}

/**
 * This functions puts an object into s3.
 * @param options
 * @param key
 * @param obj
 * @param s3
 * @param log
 * @returns obj if successful or null if failure
 */
const putJSONObjectAsync = async (options, key, body, mimetype, s3, log) => {
    const {bucket} = options;
    let params = {
        Body: body,
        Bucket: bucket,
        Key: key,
        ContentType: mimetype
    };
    // if(obj.file && options.objectType === "html") {
    //     let fileData = Buffer.from(obj.file, 'base64').toString('utf-8');
    //     fileData.replace(/\&lt;/g, "<")
    //     params = {...params, Body: fileData, Metadata: { ContentType: "text/html", ContentEncoding : "UTF-8" }}
    // }

    log.info(`Trying to putObject: ${bucket}/${key}`);
    try {
        const data = await s3.putObject(params).promise();
        log.info(`putObject successful: ${bucket}/${key}`);
        return data;
    } catch (err) {
        log.error(`Failed to putObject: ${bucket}/${key}`, err, {});
        return null;
    }
}

/**
 * This function deletes an object from s3.
 * @param options
 * @param key
 * @param s3
 * @param log
 * @returns obj empty object
 */
const deleteJSONObjectAsync = async (options, key, s3, log) => {
    const {bucket} = options;
    let params = {
        Bucket: bucket,
        Key: key
    };
    log.info(`Trying to deleteObject: ${bucket}/${key}`);
    try {
        const res = await s3.deleteObject(params).promise();
        log.info(`deleteObject successful: ${bucket}/${key}`);
        return res;
    } catch (err) {
        log.error(`Failed to deleteObject: ${bucket}/${key}`, err, {});
        return null;
    }
}

/**
 * This function lists objects in s3 and returns an array of keys.
 * @param options
 * @param prefix
 * @param s3
 * @param log
 * @returns array or null
 */
const listObjectsAsync = async (options, prefix, s3, log) => {
    const {bucket} = options;
    let params = {
        Bucket: bucket,
        Prefix: prefix
    };
    log.info(`Trying to listObjects: ${options.bucket}/${prefix}`);
    try {
        const data = await s3.listObjectsV2(params).promise();
        if (data.Contents && data.Contents.length > 0) {
            let keys = data.Contents.map(c => c.Key);
            //log.info(`listObjects data: ${keys}`);
            return keys;
        } else {
            log.warn(`listObjects not found: ${options.bucket}/${prefix}`);
            return null;
        }
    } catch (err) {
        log.error(`Failed to listObjects: ${options.bucket}/${prefix}`, err, {});
        return null;
    }
}

/**
 * This function lists objects in s3 and returns original response from s3.listObject().
 * The only difference comparing to listObjectsAsync() is that listObjectsAsync() uses listObjectV2()
 * Therefore, the params passed to each S3 list object API are different.
 * Doc: https://docs.aws.amazon.com/AWSJavaScriptSDK/latest/AWS/S3.html#listObjectsV2-property
 * @param options
 * @param prefix
 * @param s3
 * @param log
 * @returns array or null
 */
const listKeysAsync = async (options, prefix, s3, log) => {
    const {bucket: Bucket, maxKeys: MaxKeys = 1000, marker: Marker = ''} = options;
    let params = {
        Prefix: prefix,
        Bucket, MaxKeys, Marker
    };

    log.info(`Trying to listKeys: ${options.bucket}/${prefix}`);
    try {
        const data = await s3.listObjects(params).promise();
        if (data && data.Contents && data.Contents.length > 0) {
            // log.info(`listObjects data: ${data}`);
            return data;
        } else {
            log.warn(`listKeys not found: ${options.bucket}/${prefix}`);
            return null;
        }
    } catch (err) {
        log.error(`Failed to listKeys: ${options.bucket}/${prefix}`, err, {});
        return null;
    }
}


module.exports = {
    initS3Client,
    initS3ClientRegion,
    initS3TemplateLoaderClient,
    sendHttpRequestCifAsync,
    sendJsonRequestCifAsync,
    sendHttpRequestPostAsync,
    sendJsonRequestPostAsync,
    listObjectKeys,
    appendS3Options,
    uploadEmptyObject,
    queryStartsWithS3Content,
    querySearchS3Content,
    createS3Client,
    getRtCifS3LogTrailKey,
    getRtPostS3LogTrailKey,
    s3LogTrailUpload,
    listKeysAsync,
    listObjectsAsync,
    getJSONObjectAsync,
    putJSONObjectAsync,
    deleteJSONObjectAsync,
    encodeStringForS3,
    uploadFile
};
