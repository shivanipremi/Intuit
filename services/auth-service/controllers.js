"use strict";

const
    {
        initApiOptions, createErrorResponse, PayApiBaseApp, initMongoClient,
    } = require('../../lib/services/base-api-ms'),
    { initialize, initValidateOptions } = require('../../lib/services/service-base-v2'),
    md5 = require('md5'),
    userConfig = require('../../lib/schema/user-config'),
    {ObjectId} = require('mongodb'),
    // constants = require('./static/user-constants'),
    asMain = (require.main === module);

function parseOptions(argv) {
    const removeTailSlash = (str) => removeTail(str || '', '/');
    return initApiOptions(1445)
        // .option('--confirm-email-attempts <number>', 'Max number of attempts to confirm user email', 3)
        .parse(argv)
        .opts();
}

async function initResources(options) {
    return await initialize(options)
        .then(initValidateOptions('mongoUrl'))
            // 'mongoUser', 'mongoPassword'))
        .then(initMongoClient)
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

const USER_COL = 'user_details';

class UserApp extends PayApiBaseApp {

    constructor(context) {
        super(context);
    }

    registerRoutes() {
        this.initSchemaValidator(userConfig);
        const router = this.router;
        const invokeAsync = this.invokeAsync.bind(this);
        const checkValidationResults = PayApiBaseApp.checkValidationResults.bind(this);
        // Convention: methods used in the express handler will have the prefix handle
        router.post('/card/onboarding',  this.validateSchema('CardPost'), invokeAsync(this.handleCardOperations));
        router.post('/user/login', this.validateSchema('UserLogin'), invokeAsync(this.handleLogin));
        router.put('/user/resetPassword', this.validateSchema('UserPasswordReset'), invokeAsync(this.resetPassword));
        router.post('/user/verify', this.validateSchema('UserConfirmEmail'), invokeAsync(this.verifyEmail));
        router.get('/user/:id', invokeAsync(this.getUserById));
    }




    /**
     * check the db for user with given loginId and password
     *  @param req
     *  @returns {Promise<*>}
     * */
    async handleLogin(req) {
        const {log} = req;
        const reqId = req.id || 0;
        const {loginId, password} = req.body;
        const userCol = this.db.collection(USER_COL);
        let user;
        try {
            user = await userCol.findOne({loginId: loginId});
        } catch (e) {
            log.error('user login error', e, {});
            return createErrorResponse(500, 'user.login.error', 'User login error');
        }
        
        if (!user || password !== user.password) {
            log.error('user');
            return createErrorResponse(401, 'user.login.failed', 'User login failed.');
        }
        if(!user.active){
            return createErrorResponse(401, 'user.not.active', 'User email not confirmed');
        }
        delete user.password;
        delete user.securityQuestions;
        return {
            status: 200,
            content: mapUserObject(user)
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


        const query = {
            $or: [
                {email}
            ]
        };
        const user = await userCol.findOne(query);
        if (user) {
            console.log("user here", user)
            return createErrorResponse(409, 'user.email.exists', 'This email already exists.');
        }

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
    async updateCard(data, email) {
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
    }
    /**
     * Insert/Update Parent and Child Cards.
     * @param req
     * @returns {Promise<*>}
     */
    async handleCardOperations(req) {
        const { log } = req;
        // Assume schema validation already happened before
        let doc = req.body;
        console.log("===DOC====", doc)

        try {
            let {primaryUserId, childId, email, updateParentCard = false, ...body} = doc;

            if(primaryUserId && childId) {
                // update child
                return;
            }

            if(primaryUserId && updateParentCard) {
                // update primary user
                return;
            }

            if(primaryUserId) {
                // add child
                let result = await this.insertCard(doc, email, false, false);
                result.childUserId = result._id;
                return {
                    status: 200,
                    content: result
                };
            }

            let isAdmin = true, isPrimary = true;
            let result = await this.insertCard(doc, email, isAdmin, isPrimary);

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
    async getUserById(req){
        const { log } = req;
        const userCol = this.db.collection(USER_COL);
        const { id } = req.params;
        let user;
        try {
            user = await userCol.findOne({ _id: ObjectId(id) });
            if(!user){
                log.error(`user not found by id ${id}`);
                return createErrorResponse(404, 'user.not.found', 'User not found by given id');
            }
            return {
                status: 200,
                content: mapUserObject(user)
            }
        } catch (e) {
            log.error(`error finding user by id ${id}`, e, {});
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