"use strict";

const
    {
        initApiOptions, createErrorResponse, createSuccessResponse, PayApiBaseApp, initMongoClient,
    } = require('../../lib/services/base-api-ms'),
    { initialize, initValidateOptions, allowCrossDomain, parseBooleanParam } = require('../../lib/services/service-base-v2'),
    userConfig = require('../../lib/schema/user-config'),
    {ObjectId} = require('mongodb'),
    { OAuth2Client } = require('google-auth-library'),
    JWTUtil = require('../../lib/jwt-util'),
    session = require('express-session'),
{   appendS3Options, initS3Client, uploadFile, putJSONObjectAsync, initS3CmdLineOptions} = require('../../lib/s3-utils'),
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
        .option('--validate-jwt <validate-jwt>', 'Validate JWT - true/false', parseBooleanParam, false)

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


const USER_COL = 'cards';
const USER_PROFILE_COL = 'users';
const USER_CONTACTS_COL = 'contacts';
const USER_LEADS_COL = 'leads'




class UserApp extends PayApiBaseApp {

    constructor(context) {
        super(context);
        const {log, options} = context;
        this.context = context;

        this.s3Client = context.s3Client;
        this.jwtUtil = new JWTUtil(log, JWTUtil.prepareJwtOptions(options));

    }

    registerRoutes() {
        this.initSchemaValidator(userConfig);
        const router = this.router;

        this.app.use(allowCrossDomain.bind(this))
        this.app.use(session({ secret: this.options.sessionSecret, resave: false, saveUninitialized: true }));

        const invokeAsync = this.invokeAsync.bind(this);
        const validateJwt = this.jwtUtil.validateJwt.bind(this);
        const checkValidationResults = PayApiBaseApp.checkValidationResults.bind(this);

        router.post('/card/onboarding', uploadFile(5000000).any('image'), invokeAsync(this.handleCardOperations));
        router.post('/card/update', validateJwt, uploadFile(5000000).any('image'), invokeAsync(this.handleCardOperations));
        router.post('/user/login', invokeAsync(this.handleLogin));
        router.get('/cards', invokeAsync(this.getDefaultCard));
        router.get("/cardDetails", validateJwt, invokeAsync(this.getCards))
        router.get("/profile", validateJwt, invokeAsync(this.getProfile))
        router.post('/profile/update', validateJwt, uploadFile(5000000).any('image'), invokeAsync(this.updateProfile));
        router.post('/analytics', validateJwt, invokeAsync(this.saveAnlayticsData));
        router.get("/analytics", validateJwt, invokeAsync(this.getAnalyticsData))

    }




    /**
     * check the db for user with given loginId and password
     *  @param req
     *  @returns {Promise<*>}
     * */
    async handleLogin(req) {
        const {log, body} = req;
        const reqId = req.id || 0;
        const userCol = this.db.collection(USER_COL);
        const { token, primaryUserId } = body;
        console.log("credential", token, "audience", audience)
        try {
            let response = await gapiClient.verifyIdToken({ idToken: token, audience });
            let payload = response.getPayload();

            console.log("PAYLOAD FROM GOOGLE HERE", payload)

            if(payload && payload.email) {
                if(primaryUserId) {
                    let query = {
                        primaryUserId : new ObjectId(primaryUserId)
                    }
                    let user = await userCol.findOne(query, {email : 1});
                    if(!user  || user.email !== payload.email ) {
                        return createErrorResponse(400, 'user.email.mismatch', 'Onboarding email is different from signup email');
                    }
                }

                let query = {}
                if(primaryUserId) {
                    query.primaryUserId = new ObjectId(primaryUserId);
                } else {
                    query.email = payload.email
                }
                let updateOptions = {
                    $set : {
                        loginAt : new Date()
                    }
                }
                let user = await userCol.findOneAndUpdate(query, updateOptions, { returnDocument: "after" });
                console.log("üser here->>>>>>>>>>>>>>>>>from db here", user);
                let jwtPayload = {
                    primaryUserId: user._id
                }

                const jwt = this.jwtUtil.encode(jwtPayload);

                // create jwt
                return {
                    status: 200,
                    content: {
                        jwtToken: jwt,
                        userDetails: user
                    }
                };

            } else {
                return createErrorResponse(500, 'user.login.error', 'Error getting response from token');
            }

        } catch (e) {
            log.error('user login error', e, {});
            return createErrorResponse(500, 'user.login.error', 'User login error');
        }


    }


    /**
     * function to check if same email exists, if not create the card
     *  @param req
     *  @returns {Promise<*>}
     * */

    async insertCard(data, email, isAdmin, isPrimary) {
        const { db } = this;
        const userCol = db.collection(USER_COL);

        if(isPrimary) {
            const query = {
                $or: [
                    {email}
                ]
            };
            const user = await userCol.findOne(query);
            if (user) {
                return createErrorResponse(409, 'user.email.exists', 'This email already exists.');
            }
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
        console.log("========data to be inserted============", doc)
        const result = await userCol.insertOne(doc, {});
        if (result.acknowledged !== true || result.insertedId == null) {
            return createErrorResponse(500, 'user.save.error', 'Error creating user');
        }
        doc._id = result.insertedId;
        return createSuccessResponse(doc);
    }

    /**
     * function to update card details
     *  @param req
     *  @returns {Promise<*>}
     * */

    async updateCard(userId, data) {
        console.log("incoming data", data)
        const { db } = this;
        const userCol = db.collection(USER_COL);

        let {primaryUserId, _id, updateCurrentCard,...updateData} = data;
        console.log("update data ", updateData)
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

        console.log("query here", query)
        const updateOptions = {
            $set: {
                active: true,
                modifiedBy: 'demo',
                modifiedOn: new Date(),
                ...updateData
            }
        };
        console.log("update options", updateOptions)
        const writeResult = await userCol.findOneAndUpdate(query, updateOptions, {
            returnDocument: 'after'
        });
        console.log("write result", writeResult)
        if (!writeResult) {
            return createErrorResponse(400, 'card.not.found', 'Could not identify card to update');
        }
        let doc = writeResult;
        return createSuccessResponse(doc);

    }


    /**
     * Get user by Id
     * @param req
     * @returns {Promise <*>}
     */
    async getDefaultCard(req){
        const { log } = req;
        let { primaryUserId, type = 'DIGITAL' } = req.query;
        console.log("query", req.query)
        const userCol = this.db.collection(USER_COL);
        const userProfileCol = this.db.collection(USER_PROFILE_COL);
        if(!primaryUserId) {
            log.error("primaryUserId should be present in the request");
            return createErrorResponse(400, 'card.primaryUserId.missing', 'primaryUserId should be present in the request');
        }
        try {
            let query ={
                primaryUserId : new ObjectId(primaryUserId)
            };

            console.log("query", query)
            let profileInfo = await userProfileCol.findOne(query);
            console.log("profileinfo", profileInfo)
            if(!profileInfo ) {
                return createErrorResponse(400, 'profile.not.exists', 'Profile doesnt exist for this email id');
            }
            query = {
                _id : new ObjectId(profileInfo.defaultCard),
                type
            }
            console.log("query2", query)

            let cardInfo = await userCol.findOne(query);
            console.log("card info", cardInfo)


            return {
                status: 200,
                content: {
                    profileInfo, cardInfo
                }
            }
        } catch (e) {
            log.error(`error finding user(id- ${id} )`, e, {});
            return createErrorResponse(500, 'user.find.error', 'Error finding user');
        }
    }


    /**
    * Get user by Id
    * @param req
    * @returns {Promise <*>}
    */
    async getCards(req){
        const { log, headers } = req;
        let { id, primaryUserId, type = 'DIGITAL' } = req.query;
        if(headers.jwtToken) {
            let payload = this.jwtUtil.decode(headers.jwtToken);
            console.log("<<<<------------------payload--------------->>>>", payload);
            primaryUserId = payload.primaryUserId;
            console.log("primaryUserId from jwt token", primaryUserId)
        }
        console.log("query", req.query)
        const userCol = this.db.collection(USER_COL);
        if(!id && !primaryUserId) {
            log.error("Either id/primaryUserId should be present in the request");
            return createErrorResponse(400, 'card.id.primaryUserId.missing', 'Either id/primaryUserId should be present in the request');
        }
        let users = [];
        try {
            let query ={};

            if(primaryUserId) {
                query = {
                    $or: [
                        { _id: new ObjectId(primaryUserId) }, // Matching documents with _id equal to primaryUserId
                        { primaryUserId: new ObjectId(primaryUserId) } // Matching documents with primaryUserId field equal to primaryUserId
                    ]
                };
            }
            if(id) {
                query._id = new ObjectId(id);
            }
            query.type = type;
            console.log("query", query)
            users = await userCol.find(query).sort({ modifiedOn: -1 }).toArray();

            return {
                status: 200,
                content: users
            }
        } catch (e) {
            log.error(`error finding user(id- ${id} )`, e, {});
            return createErrorResponse(500, 'user.find.error', 'Error finding user');
        }
    }

    /**
     * Handle card operations, add and update child card, add and update primary card
     * @param req
     * @returns {Promise <*>}
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
        doc.type = doc.type || 'DIGITAL';
        let fileKey ='';

        try {
            // upload files
            if(files && files.length) {
                for(let file of files) {
                    let ext = file.mimetype.split('/');
                    let fileName = file.fieldname;
                    fileKey = `user/${fileToken}.${ext[ext.length - 1]}`;
                    let uploadResponse = await putJSONObjectAsync(s3Options, fileKey, file.buffer, file.mimetype, s3Client, log);
                    if(!uploadResponse) {
                        return createErrorResponse(500, 'image.upload.error', 'Error in uploading image.');
                    }
                    doc[fileName] = `${options.s3Url}/${fileKey}`;
                }
            }

            let {primaryUserId, _id, updateCurrentCard = false, defaultCardType = 'card-design-1',...body} = doc;


            // need to refreactor this part, either delete file if some error occured/do update ioperation to update the url


            console.log("doc here", body)


            if(_id && updateCurrentCard) {
                console.log("==================Updating user=====================", _id)
                // update child
                try {
                    // let result =  await this.updateCard(_id, doc);
                    // return {
                    //     status: 200,
                    //     content: result
                    // };

                    return await this.updateCard(_id, doc);

                } catch(err) {
                    console.log("error here", err)
                }
            }
            if(primaryUserId) {
                console.log("=========Add Child=============", primaryUserId);
                // if(!primaryUserId) {
                //     return createErrorResponse(422, 'user.save.error', 'Primary User Id not present.');
                // }

                // add child
                body.primaryUserId = new ObjectId(primaryUserId);
                body.isChild = true;
                return await this.insertCard(body, body.email, false, false);

            }

            console.log("===================Insert Primary Card=====================")
            // Case : Add primary User
            let isAdmin = true, isPrimary = true;
            let result = await this.insertCard(body, body.email, isAdmin, isPrimary);
            console.log("RESULT HERE-----------------", result)
            if(result.status != 200 || !result.content) {
                return result;
            }
            let profile = result.content;


            // Since, this is a primary user, create a profile

            const { db } = this;
            const userProfileCol = db.collection(USER_PROFILE_COL);

            profile.primaryUserId = new ObjectId(result._id);
            profile.defaultCard = new ObjectId(result._id);
            profile.defaultCardType = defaultCardType;
            console.log("profile here",profile)
            const insertedProfile = await userProfileCol.insertOne(profile, {});
            if (insertedProfile.acknowledged !== true || insertedProfile.insertedId == null) {
                return createErrorResponse(500, 'user.profile.save.error', 'Error creating user profile');
            }
            console.log("reuslt final", result)

            return {
                status: 200,
                content: profile
            };
        } catch (err) {
            log.error('user save error', err, {});
            return createErrorResponse(500, 'user.save.error', 'Error creating user');
        }
    }


    /**
     * Update primary Card Profile
     * @param req
     * @returns {Promise <*>}
     */
    async updateProfile(req) {

        const {files, log, headers} = req;
        const { s3Client, options, db } = this;
        const userProfileCol = db.collection(USER_PROFILE_COL);
        const { s3Bucket } = options;
        let s3Options = { bucket: s3Bucket };
        let idToUpdate;

        // Assume schema validation already happened before
        let doc = req.body;
        let fileKey ='';

        try {
            if(!headers.jwtToken) {
                return createErrorResponse(400, 'jwt.token.not.prcoessed', 'JWT token was not processed in the request');
            }

            let payload = this.jwtUtil.decode(headers.jwtToken);
            console.log("<<<<------------------payload--------------->>>>", payload);
            idToUpdate = payload.primaryUserId;
            console.log("primaryUserId from jwt token", idToUpdate)

            // upload files
            if(files && files.length) {
                for(let file of files) {
                    let ext = file.mimetype.split('/');
                    let fileName = file.fieldname;
                    fileKey = `user/${fileToken}.${ext[ext.length - 1]}`;
                    let uploadResponse = await putJSONObjectAsync(s3Options, fileKey, file.buffer, file.mimetype, s3Client, log);
                    if(!uploadResponse) {
                        return createErrorResponse(500, 'image.upload.error', 'Error in uploading image.');
                    }
                    doc[fileName] = `${options.s3Url}/${fileKey}`;
                }
            }

            let {primaryUserId, _id, updateCurrentCard = false, ...body} = doc;

            console.log("==========body=========", body)


            if(body.email) {
                const query = {
                    primaryUserId: {$ne: new ObjectId(idToUpdate)},
                    email: body.email
                };
                let checkIfEmailExists = await userProfileCol.findOne(query);
                if (checkIfEmailExists) {
                    console.log("email id already exists")
                    return createErrorResponse(409, 'user.email.exists', 'This email already exists.');
                }
            }

            let query = {
                primaryUserId : new ObjectId(idToUpdate)
            }

            console.log("query here", query)
            const updateOptions = {
                $set: {
                    active: true,
                    modifiedBy: 'demo',
                    modifiedOn: new Date(),
                    createdOn : new Date(),
                    ...body
                }
            };
            console.log("update options", updateOptions)
            const writeResult = await userProfileCol.findOneAndUpdate(query, updateOptions, {
                returnDocument: 'after'
            });
            console.log("write result", writeResult)
            if (!writeResult) {
                return createErrorResponse(400, 'profile.not.found', 'Could not identify prfile to update');
            }
            let result = writeResult;

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
     * Save contact/leads
     * @param req
     * @returns {Promise <*>}
     */
    async saveAnlayticsData(req) {

        const {log, headers} = req;
        const { db } = this;
        let collectionName;

        // Assume schema validation already happened before
        let doc = req.body;

        try {
            if(!headers.jwtToken || !doc.type) {
                console.log("400", headers, doc.type)
                return createErrorResponse(400, 'jwt.token.or.type.not.present', 'JWT token or type was not processed in the request');
            }
            console.log("jwtToken", headers.jwtToken)
            let payload = this.jwtUtil.decode(headers.jwtToken);
            console.log("<<<<------------------payload--------------->>>>", payload);
            let primaryUserId  = payload.primaryUserId;
            console.log("primaryUserId from jwt token", primaryUserId)

            let {type, _id,...body} = doc;
            if(type == "CONTACTS") {
                collectionName = db.collection(USER_CONTACTS_COL);
            } else {
                collectionName = db.collection(USER_LEADS_COL);

            }
            let dataToInsert = {
                id : _id,
                primaryUserId : new ObjectId(primaryUserId),
                ...body,
                submittedOn : new Date(),
                createdOn : new Date(),
                updatedOn: new Date()
            }

            const result = await collectionName.insertOne(dataToInsert, {});
            if (result.acknowledged !== true || result.insertedId == null) {
                return createErrorResponse(500, 'contact.save.error', 'Error inserting contact');
            }
            console.log("write result", result)

            return {
                status: 200,
                content: result
            }
        } catch (err) {
            log.error('user save error', err, {});
            return createErrorResponse(500, 'user.save.error', 'Error creating user');
        }
    }

    /**
     * Get user by Id
     * @param req
     * @returns {Promise <*>}
     */
    async getAnalyticsData(req){
        const { log, headers } = req;
        let { type, searchText } = req.query;
        console.log("type here", type)
        let payload = this.jwtUtil.decode(headers.jwtToken);
        console.log("<<<<------------------payload--------------->>>>", payload);
        let primaryUserId = payload.primaryUserId;
        console.log("primaryUserId from jwt token", primaryUserId);
        let collectionName;

        if(!primaryUserId || !type) {
            log.error("Either id/primaryUserId should be present in the request");
            return createErrorResponse(400, 'card.id.primaryUserId.missing', 'Either id/primaryUserId should be present in the request');
        }
        if(type == "CONTACTS") {
            collectionName = this.db.collection(USER_CONTACTS_COL);
        } else {
            collectionName = this.db.collection(USER_LEADS_COL);
        }
        try {
            let query ={
                primaryUserId : new ObjectId(primaryUserId)
            };
            if(searchText) {
                query["$or"] = [
                    { name: { $regex: searchText, $options: 'i' } }, // Case-insensitive regex match for contact field
                    { email: { $regex: searchText, $options: 'i' } },    // Case-insensitive regex match for name field
                    { phoneNo: { $regex: searchText, $options: 'i' } }    // Case-insensitive regex match for phone field
                ]
            }

            console.log("query get", query)
            let data = await collectionName.find(query).sort({ modifiedOn: -1 }).toArray();

            return {
                status: 200,
                content: data
            }
        } catch (e) {
            log.error(`error finding data`, e, {});
            return createErrorResponse(500, 'data.find.error', 'Error finding data');
        }
    }
    /**
     * Get profile by token
     * @param req
     * @returns {Promise <*>}
     */
    async getProfile(req){
        const { log, headers } = req;

        let payload = this.jwtUtil.decode(headers.jwtToken);
        console.log("<<<<------------------payload--------------->>>>", payload);
        let primaryUserId = payload.primaryUserId;
        console.log("primaryUserId from jwt token", primaryUserId)

        const userProfileCol = this.db.collection(USER_PROFILE_COL);
        if(!primaryUserId) {
            log.error("primaryUserId should be present in the request");
            return createErrorResponse(400, 'profile.primaryUserId.missing', 'primaryUserId should be present in the request');
        }
        try {
            let query = {
                primaryUserId : new ObjectId(primaryUserId)
            };

            console.log("query", query)
            let users = await userProfileCol.find(query).sort({ modifiedOn: -1 }).toArray();
            // if(!user){
            //     log.error(`user not found by id ${id}`);
            //     return createErrorResponse(404, 'user.not.found', 'User not found by given id');
            // }

            // get user cards
            // get user saved contacts/leads/visits/

            return {
                status: 200,
                content: users
            }
        } catch (e) {
            log.error(`error finding user`, e, {});
            return createErrorResponse(500, 'user.profile.find.error', 'Error finding user profile');
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