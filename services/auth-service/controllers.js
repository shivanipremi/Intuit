"use strict";

const
    {
        initApiOptions, createErrorResponse, PayApiBaseApp, initMongoClient,
    } = require('../../lib/services/base-api-ms'),
    { initialize, initValidateOptions, allowCrossDomain } = require('../../lib/services/service-base-v2'),
    md5 = require('md5'),
    userConfig = require('../../lib/schema/user-config'),
    {ObjectId} = require('mongodb'),
    { OAuth2Client } = require('google-auth-library'),
    {google} = require('googleapis'),
     session = require('express-session'),
{   appendS3Options, initS3Client, uploadFile, putJSONObjectAsync, initS3CmdLineOptions} = require('../../lib/s3-utils'),
// constants = require('./static/user-constants'),
    asMain = (require.main === module);

let gapiClient;
let audience;

function initGoogleAuthClient(context) {
    audience = context.options.googleClientId;
    gapiClient = new OAuth2Client(audience, '', '');
    return context;
}


function parseOptions(argv) {
    let options = initApiOptions(1473)
        .option('--session-secret <session secret>', 'Session secret used to sign session IDs',)
        .option('--google-client-id <Client Id>', 'Google client ID')
        .option('--google-client-secret <client secret>', 'Google client ID')


    appendS3Options(options);
    let opts = options
        .parse(argv)
        .opts();
    return opts;
}


async function initResources(options) {

    return await initialize(options)
        .then(initValidateOptions('mongoUrl', 'mongoUser', 'mongoPassword', 'googleClientId', 'googleClientSecret',))
        .then(initS3CmdLineOptions)
        .then(initS3Client)
        .then(initMongoClient)
        .then(initGoogleAuthClient)
}



function mapUserObject(user){
    delete user.email;
    delete user.modifiedOn;
    delete user.createdOn;
    delete user.modifiedBy;
    delete user.createdBy;
    delete user.active;
    delete user.issuer;
    delete user.confirmToken;
    delete user.confirmEmailAttempts;
    return user;
}

const USER_COL = 'cards';


class UserApp extends PayApiBaseApp {

    constructor(context) {
        super(context);
        this.context = context;
        this.s3Client = context.s3Client;
    }

    registerRoutes() {
        this.initSchemaValidator(userConfig);
        const router = this.router;

        this.app.use(allowCrossDomain.bind(this))
        this.app.use(session({ secret: this.options.sessionSecret, resave: false, saveUninitialized: true }));




        const invokeAsync = this.invokeAsync.bind(this);
        const checkValidationResults = PayApiBaseApp.checkValidationResults.bind(this);

        // router.post('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));




        router.post('/card/onboarding', uploadFile(5000000).any('image'), invokeAsync(this.handleCardOperations));
        router.post('/card/update', uploadFile(5000000).any('image'), invokeAsync(this.handleCardOperations));
        router.post('/user/login', invokeAsync(this.handleLogin));
        router.put('/user/resetPassword', this.validateSchema('UserPasswordReset'), invokeAsync(this.resetPassword));
        router.post('/user/verify', this.validateSchema('UserConfirmEmail'), invokeAsync(this.verifyEmail));
        router.get('/cards', invokeAsync(this.getCards));

    }




    /**
     * check the db for user with given loginId and password
     *  @param req
     *  @returns {Promise<*>}
     * */
    async handleLogin(req) {
        const {log, body} = req;
        const reqId = req.id || 0;
        const { token } = body;
        console.log("credential", token, "audience", audience)
        try {
            let response = await gapiClient.verifyIdToken({ idToken: token, audience });
            console.log("RESPONSE FROM GOOGLE HERE", response)
            let payload = response.getPayload();
            console.log("PAYLOAD FROM GOOGLE HERE", payload)

        } catch (e) {
            log.error('user login error', e, {});
            return createErrorResponse(500, 'user.login.error', 'User login error');
        }

        return {
            status: 200,
            content: {}
        };
    }


    /**
     * function to check if same email exists, if not create the card
     *  @param req
     *  @returns {Promise<*>}
     * */

    async insertCard(data, email, isAdmin, isPrimary) {
        const { db } = this;
        const userCol = db.collection(USER_COL);
        // const query = {
        //     $or: [
        //         {email}
        //     ]
        // };
        // const user = await userCol.findOne(query);
        // if (user) {
        //     return createErrorResponse(409, 'user.email.exists', 'This email already exists.');
        // }

        let doc = {
            email,
            active: true,
            isPrimary,
            isAdmin,
            modifiedOn: new Date(),
            createdOn: new Date(),
            createdBy: 'demo',
            modifiedBy: 'demo',
            ...data
        };
        console.log("========data to be inserted============", doc)
        const result = await userCol.insertOne(doc, {});
        if (result.acknowledged !== true || result.insertedId == null) {
            return createErrorResponse(500, 'user.save.error', 'Error creating user');
        }
        doc._id = result.insertedId;
        return doc;
    }


    /**
     * function to update card details
     *  @param req
     *  @returns {Promise<*>}
     * */
    async updateCard(userId, data) {
        const { db } = this;
        const userCol = db.collection(USER_COL);

        let {primaryUserId, _id, updateCurrentCard,...updateData} = data
        // update primary user
        // if(data.email) {
        //     const query ={
        //         _id : {$ne : new ObjectId(userId)},
        //         email : data.email
        //     };
        //     let checkIfEmailExists = await userCol.findOne(query);
        //     if (checkIfEmailExists) {
        //         return createErrorResponse(404, 'email.already.exists', 'This email id already exists')
        //     }
        // }

        const query = {
            _id : new ObjectId(userId)
        };
        // if(parentId) {
        //     query.primaryUserId = new ObjectId(parentId)
        // }

        console.log("query here", query)
        const updateOptions = {
            $set: {
                active: true,
                modifiedBy: 'demo',
                modifiedOn: new Date(),
                ...updateData
            }
        };
        const writeResult = await userCol.findOneAndUpdate(query, updateOptions, {
            returnDocument: 'after'
        });
        console.log("write result", writeResult)
        if (!writeResult) {
            return createErrorResponse(404, 'card.not.found', 'Could not identify card to update');
        }
        let doc = writeResult;
        return doc;
    }
    /**
     * Insert/Update Parent and Child Cards.
     * @param req
     * @returns {Promise<*>}
     */
    async handleCardOperations(req) {

        const {files } = req;
        const { s3Client, log, options } = this;
        const { s3Bucket } = options;
        let s3Options = { bucket: s3Bucket };

        const chars = [..."ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"];
        let fileToken = [...Array(8)].map(i=>chars[Math.random()*chars.length|0]).join``;

        // Assume schema validation already happened before
        let doc = req.body;
        let fileKey ='';

        try {
            let {primaryUserId, _id, updateCurrentCard = false, ...body} = doc;

            // need to refreactor this part, either delete file if some error occured/do update ioperation to update the url
            if(files && files.length) {
                for(let file of files) {
                    let ext = file.mimetype.split('/');
                    let fileName = file.fieldname;
                    fileKey = `user/${fileToken}.${ext[ext.length - 1]}`;
                    let uploadResponse = await putJSONObjectAsync(s3Options, fileKey, file.buffer, file.mimetype, s3Client, log);
                    if(!uploadResponse) {
                        return createErrorResponse(500, 'image.upload.error', 'Error in uploading image.');
                    }
                    body[fileName] = `${options.s3Url}/${fileKey}`;
                }
            }

            console.log("doc here", body)


            if(_id && updateCurrentCard) {
                console.log("==================Updating user=====================", _id)
                // update child
                try {
                    let result =  await this.updateCard(_id, doc);
                    return {
                        status: 200,
                        content: result
                    };

                } catch(err) {
                    console.log("error here", err)
                }
            }
            if(_id) {
                console.log("=========Add Child=============", _id)

                // add child
                body.primaryUserId = new ObjectId(_id);
                body.isChild = true;
                let result = await this.insertCard(body, body.email, false, false);
                result.childUserId = result._id;
                return {
                    status: 200,
                    content: result
                };
            }
            // Case : Add primary User
            let isAdmin = true, isPrimary = true;
            let result = await this.insertCard(body, body.email, isAdmin, isPrimary);
            result.primaryUserId = result._id;
            return {
                status: 200,
                content: result
            };
        } catch (err) {
            log.error('user save error', err, {});
            return createErrorResponse(500, 'user.save.error', 'Error creating user');
        }
    }

    /**
     * Reset user password.
     * @param req
     * @returns {Promise<*>}
     */
    async resetPassword(req) {
        const { log } = req;
        const userCol = this.db.collection(USER_COL);
        // Assume schema validation already happened before
        let doc = req.body;
        try {
            let {loginId, password, securityQuestions} = doc;
            let query = {loginId, active: {$in: [true]}};
            const userData = await userCol.findOne(query);

            if (!userData) {
                return createErrorResponse(404, 'user.not.found', 'User not found');
            }
            for (let securityQuestion of securityQuestions) {
                let question = userData.securityQuestions.find(q => q.id === securityQuestion.id);
                if (!question) {
                    return createErrorResponse(422, 'securityQuestion.id.not.found', `Security Question with id ${securityQuestion.id} not found for TLA`);
                }
                if (question.answer.trim().toLowerCase() !== securityQuestion.answer.trim().toLowerCase()) {
                    return createErrorResponse(401, 'user.invalid.security.answer', `Invalid Security answer`);
                }
            }
            query = {
                loginId, active: {$in: [true, false]}
            };

            const updateOptions = {
                $set: {
                    password, // update all fields sent
                    passwordModifiedOn: new Date(),
                    modifiedOn: new Date()
                    // modifiedBy: issuer
                }
            };
            const writeResult = await userCol.updateOne(query, updateOptions);
            if (!writeResult || writeResult.acknowledged !== true || writeResult.modifiedCount === 0) {
                return createErrorResponse(404, 'user.not.found', 'User not found');
            }
            doc = userData;
            await this.sendEmail(log, doc.email, {supportEmail: (req.body.supportEmail || this.options.supportEmail)}, 'mobile-ipn-password-reset', 'Account password reset');
        } catch (err) {
            log.error('Error updating user password', err, {});
            return createErrorResponse(500, 'user.update.password.error', 'Error updating password of User');
        }

        log.info(`Password updated`);
        return {
            status: 200,
            content: mapUserObject(doc)
        };
    }


    /**
     * Change user password.
     * @param req
     * @returns {Promise<*>}
     */
    async verifyEmail(req) {
        const { log } = req;
        const userCol = this.db.collection(USER_COL);
        let doc = req.body;
        // Assume schema validation already happened before
        try {
            let {loginId, token} = doc;
            const query = {loginId, active: {$in: [false]}};
            const updateOptions = {
                $set: {
                    active: true,
                    // modifiedBy: issuer,
                    modifiedOn: new Date()
                },
                $unset: {
                    confirmToken: 1,
                    confirmEmailAttempts: 1
                }
            };
            let user = await userCol.findOne(query);
            if (!user) {
                return createErrorResponse(404, 'user.not.found', 'User not found by loginId')
            }
            if(user.confirmEmailAttempts >= this.options.confirmEmailAttempts){
                return createErrorResponse(403, 'confirm.email.attempts.exceeded', 'Max number of attempts to confirm email exceeded');
            }
            if (user.confirmToken !== token) {
                await userCol.findOneAndUpdate(query, {$inc: {confirmEmailAttempts : 1}});
                return createErrorResponse(422, 'confirm.email.token.mismatch', 'Incorrect value of confirm email token');
            }
            const writeResult = await userCol.findOneAndUpdate(query, updateOptions, {
                returnDocument: 'after'
            });
            if (writeResult.ok !== 1 || writeResult.lastErrorObject.n === 0) {
                return createErrorResponse(404, 'user.not.found', 'Could not identify user to update');
            }
            doc = writeResult.value;
        } catch (err) {
            // FIXME: Identify mongo exceptions that we should return specific errors.
            log.error('user confirm email error', err, {});
            return createErrorResponse(500, 'user.confirmEmail.error', 'Error confirming user email');
        }
        return {
            status: 200,
            content: mapUserObject(doc)
        };
    }

    /**
    * Get user by Id
    * @param req
    * @returns {Promise <*>}
    */
    async getCards(req){
        const { log } = req;
        const userCol = this.db.collection(USER_COL);
        const { id, primaryUserId } = req.query;
        let users = [];
        try {
            let query ={};
            if(id) {
                query._id = new ObjectId(id);
            }
            if(primaryUserId) {
                query.primaryUserId = new ObjectId(primaryUserId)
            }
            console.log("query", query)
            users = await userCol.find(query).sort({ modifiedOn: -1 }).toArray();
            // if(!user){
            //     log.error(`user not found by id ${id}`);
            //     return createErrorResponse(404, 'user.not.found', 'User not found by given id');
            // }
            return {
                status: 200,
                content: users
            }
        } catch (e) {
            log.error(`error finding user(id- ${id} )`, e, {});
            return createErrorResponse(500, 'user.find.error', 'Error finding user');
        }
    }

}

// Run the application, and export module for testing.
if (asMain) {
    const options = parseOptions(process.argv);
    let app;
    initResources(options)
        .then(context => {
            app = new UserApp(context).run();
        })
        .catch(async (err) => {
            console.error('Failed to initialize', err.stack || err);
            process.exit(1);
        });
}

module.exports = { UserApp, parseOptions, initResources };