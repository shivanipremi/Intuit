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

async function initS3CmdLineOptions(context) {
    const { options } = context;
    context.options = {
        ...options,
        s3AccessKey: options.s3AccessKey,
        s3SecretKey: options.s3SecretKey,
        s3Region: options.s3Region,
        s3Bucket: options.s3Bucket,
    };

    return context;
}

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
    initS3CmdLineOptions,
    initS3ClientRegion,
    listObjectKeys,
    appendS3Options,
    uploadEmptyObject,
    createS3Client,
    listKeysAsync,
    listObjectsAsync,
    getJSONObjectAsync,
    putJSONObjectAsync,
    deleteJSONObjectAsync,
    uploadFile
};
