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
    path = require('path'),
    fs = require('fs'),
    axios = require('axios'),
    bcrypt = require('bcryptjs'),
    stripe = require('stripe')(process.env.STRIPE_SECRET_KEY),
{   appendS3Options, initS3Client, uploadFile, putJSONObjectAsync, initS3CmdLineOptions} = require('../../lib/s3-utils'),
    asMain = (require.main === module);



console.log("=============", process.env.STRIPE_SECRET_KEY)
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
        .option('--app-host <app-host>', 'App Host')
        .option('--ssl-key <ssl-key>', 'SSl key')
        .option('--ssl-cert <ssl-key>', 'ssl cert')



    appendS3Options(options);
    let opts = options
        .parse(argv)
        .opts();
    return opts;
}


async function initResources(options) {

    return await initialize(options)
        .then(initValidateOptions('mongoUrl', 'mongoUser', 'mongoPassword', 'googleClientId', 'googleClientSecret', 'appHost'))
        // .then(initS3CmdLineOptions)
        // .then(initS3Client)
        .then(initMongoClient)
        .then(initGoogleAuthClient)
}


const USER_COL = 'cards';
const USER_PROFILE_COL = 'users';
const USER_CONTACTS_COL = 'contacts';
const USER_LEADS_COL = 'leads'
const uploadDir = path.join(__dirname, '../../uploads');





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
        this.app.use("/uploads", this.express.static(uploadDir));


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
        router.post('/contact', validateJwt, invokeAsync(this.saveAnlayticsData));
        router.get("/contacts", validateJwt, invokeAsync(this.getAnalyticsData))
        router.get("/dashboard", validateJwt, invokeAsync(this.getDashboardData));
        router.post("/payment", validateJwt, invokeAsync(this.makePayment));
        router.post("/verifyPayment", validateJwt, invokeAsync(this.verifyPayment))


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
        let { token, primaryUserId, email, type = 'GOOGLE', password } = body;
        console.log("body", body)
        console.log("credential", token, "audience", audience)
        try {
            if(type == 'GOOGLE') {
                let response = await gapiClient.verifyIdToken({ idToken: token, audience });
                let payload = response.getPayload();
                if(!payload || !payload.email) {
                    return createErrorResponse(500, 'user.login.error', 'Error getting response from token');

                }
                email = payload.email
            } else if(type == 'FACEBOOK') {
                const response = await axios.get(`https://graph.facebook.com/me?access_token=${token}&fields=id,name,email`);
                console.log("RESPONSE HERE====", response);
                if(response) {
                    email = response.email;
                }
            }
            if(primaryUserId) {
                let query = {
                    _id : new ObjectId(primaryUserId)
                }

                let user = await userCol.findOne(query, {email : 1});
                if(!user  || user.email !== email ) {
                    return createErrorResponse(400, 'user.email.mismatch', 'Onboarding email is different from signup email');
                }
            }

            let query = {}
            if(primaryUserId) {
                query._id = new ObjectId(primaryUserId);
            } else {
                query.email = email
            }

            if(type == 'EMAIL') {
                let userDetails = await userCol.findOne(query);
                if(!userDetails) {
                    return createErrorResponse(400, 'email.does.not.exist', 'Email does not exist');
                }
                if(userDetails.password) {
                    const isMatch = await bcrypt.compare(password, userDetails.password);
                    if (!isMatch) {
                        return createErrorResponse(400, 'incorrect.password.or.email', 'Please enter valid email id and passworkd');
                    }
                    password = userDetails.password;
                } else {
                    const salt = await bcrypt.genSalt(10);
                    password = await bcrypt.hash(password, salt);
                }
            }

            let updateOptions = {
                $set : {
                    loginAt : new Date()
                }
            }
            if(type == 'EMAIL') {
                updateOptions["$set"]["password"] = password;
            }

            console.log("query here", {query, updateOptions})
            let user = await userCol.findOneAndUpdate(query, updateOptions, { returnDocument: "after" });
            let jwtPayload = {
                primaryUserId: user._id
            }

            const jwt = this.jwtUtil.encode(jwtPayload);

            delete user.password;

            // create jwt
            return {
                status: 200,
                content: {
                    jwtToken: jwt,
                    userDetails: user
                }
            };



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

    async insertCard(data, email, isAdmin, isPrimary, files) {
        const { db, options } = this;
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

        const filesUploaded = await this.uploadFilesToServer(files, options.appHost, options.port);
        console.log("files to upload", filesUploaded)

        let doc = {
            email,
            active: true,
            isPrimary,
            isAdmin,
            modifiedOn: new Date(),
            createdOn: new Date(),
            createdBy: 'demo',
            modifiedBy: 'demo',
            isDeleted: 0,
            ...data,
            ...filesUploaded
        };
        const result = await userCol.insertOne(doc, {});
        if (result.acknowledged !== true || result.insertedId == null) {
            return createErrorResponse(500, 'user.save.error', 'Error creating user');
        }
        doc._id = result.insertedId;
        return createSuccessResponse(doc);
    }

    async uploadFilesToServer(files, appHost, port) {
        try {
            let fileMap = {}
            const fileSavePromises = files.map((file) => {
                let name = `${Date.now()}-${file.originalname}`
                let relativeFilePath = `${appHost}:${port}/uploads/${name}`
                const filePath = path.join(uploadDir, name);
                return new Promise((resolve, reject) => {
                    fs.writeFile(filePath, file.buffer, (err) => {
                        if (err) {
                            reject(err);
                        } else {
                            const fileName = file.fieldname;
                            resolve({ [fileName]: relativeFilePath });
                        }
                    });
                });
            });

            let result = await Promise.all(fileSavePromises);
            if(result?.length) {
                fileMap = result.reduce((acc, cur) => ({ ...acc, ...cur }), {});
                console.log(fileMap);
            }
            return fileMap;




        } catch (error) {
            console.log("Error occured while saving files")
            throw error;
        }
    }




    /**
     * function to update card details
     *  @param req
     *  @returns {Promise<*>}
     * */

    async updateCard(userId, data, files) {
        try {
            const { db, options } = this;
            const userCol = db.collection(USER_COL);

            let {primaryUserId, _id, updateCurrentCard, isDeleted, ...updateData} = data;
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

            const filesUploaded = await this.uploadFilesToServer(files, options.appHost, options.port);
            console.log("files to upload", filesUploaded)
            const updateOptions = {
                $set: {
                    active: true,
                    modifiedBy: 'demo',
                    modifiedOn: new Date(),
                    isDeleted : isDeleted == 1 ? 1 : 0,
                    ...updateData,
                    ...filesUploaded
                }
            };
            const writeResult = await userCol.findOneAndUpdate(query, updateOptions, {
                returnDocument: 'after'
            });
            if (!writeResult) {
                return createErrorResponse(400, 'card.not.found', 'Could not identify card to update');
            }
            let doc = writeResult;
            return createSuccessResponse(doc);

        } catch(err) {
            throw err;
        }
    }


    /**
     * Get user by Id
     * @param req
     * @returns {Promise <*>}
     */
    async getDefaultCard(req){
        const { log } = req;
        let { primaryUserId, type = 'DIGITAL' } = req.query;
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

            let profileInfo = await userProfileCol.findOne(query);
            if(!profileInfo ) {
                return createErrorResponse(400, 'profile.not.exists', 'Profile doesnt exist for this email id');
            }
            query = {
                _id : new ObjectId(profileInfo.defaultCard),
                type
            }

            let cardInfo = await userCol.findOne(query);

            return {
                status: 200,
                content: {
                    profileInfo, cardInfo
                }
            }
        } catch (e) {
            log.error(`error finding user(id-)`, e, {});
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
            primaryUserId = payload.primaryUserId;
        }
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
            query.isDeleted = 0;
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
        const {log, options } = this;


        // Assume schema validation already happened before
        let doc = req.body;
        doc.type = doc.type || 'DIGITAL';

        try {

            let {primaryUserId, _id, updateCurrentCard = false,...body} = doc;


            if(_id && updateCurrentCard) {
                console.log("Updating user...", _id)
                return await this.updateCard(_id, doc, files);
            }

            if(primaryUserId) {
                console.log("Add Child...", primaryUserId);
                // add child
                body.primaryUserId = new ObjectId(primaryUserId);
                body.isChild = true;
                return await this.insertCard(body, body.email, false, false, files);
            }

            console.log("Insert Primary Card..")
            // Case : Add primary User
            let isAdmin = true, isPrimary = true;
            let result = await this.insertCard(body, body.email, isAdmin, isPrimary, files);
            if(result.status != 200 || !result.content) {
                return result;
            }
            let profile = result.content;

            console.log("Inserting profile..")
            const { db } = this;
            const userProfileCol = db.collection(USER_PROFILE_COL);
            profile.primaryUserId = new ObjectId(profile._id);
            profile.defaultCard = new ObjectId(profile._id);
            // profile.defaultCardType = defaultCardType;
            delete profile._id
            const insertedProfile = await userProfileCol.insertOne(profile, {});
            if (insertedProfile.acknowledged !== true || insertedProfile.insertedId == null) {
                return createErrorResponse(500, 'user.profile.save.error', 'Error creating user profile');
            }
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
        console.log("FILES HERE", files)
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
            idToUpdate = payload.primaryUserId;

            // upload files
            // if(files && files.length) {
            //     for(let file of files) {
            //         let ext = file.mimetype.split('/');
            //         let fileName = file.fieldname;
            //         fileKey = `user/${fileToken}.${ext[ext.length - 1]}`;
            //         let uploadResponse = await putJSONObjectAsync(s3Options, fileKey, file.buffer, file.mimetype, s3Client, log);
            //         if(!uploadResponse) {
            //             return createErrorResponse(500, 'image.upload.error', 'Error in uploading image.');
            //         }
            //         doc[fileName] = `${options.s3Url}/${fileKey}`;
            //     }
            // }


            let {primaryUserId, _id, updateCurrentCard = false, ...body} = doc;

            if(body.email) {
                const query = {
                    primaryUserId: {$ne: new ObjectId(idToUpdate)},
                    email: body.email
                };
                let checkIfEmailExists = await userProfileCol.findOne(query);
                if (checkIfEmailExists) {
                    return createErrorResponse(409, 'user.email.exists', 'This email already exists.');
                }
            }
            const filesUploaded = await this.uploadFilesToServer(files, options.appHost, options.port);

            let query = {
                primaryUserId : new ObjectId(idToUpdate)
            }
            const updateOptions = {
                $set: {
                    active: true,
                    modifiedBy: 'demo',
                    modifiedOn: new Date(),
                    createdOn : new Date(),
                    ...body,
                    ...filesUploaded
                }
            };
            const writeResult = await userProfileCol.findOneAndUpdate(query, updateOptions, {
                returnDocument: 'after'
            });
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
        // Assume schema validation already happened before
        let doc = req.body;

        try {
            if(!headers.jwtToken || !doc.type) {
                return createErrorResponse(400, 'jwt.token.or.type.not.present', 'JWT token or type was not processed in the request');
            }
            let payload = this.jwtUtil.decode(headers.jwtToken);
            let primaryUserId  = payload.primaryUserId;

            let {_id,...body} = doc;
            let collectionName = db.collection(USER_CONTACTS_COL);

            let dataToInsert = {
                id : _id,
                ...body,
                primaryUserId : new ObjectId(primaryUserId),
                submittedOn : new Date(),
                createdOn : new Date(),
                updatedOn: new Date(),
            }

            const result = await collectionName.insertOne(dataToInsert, {});
            if (result.acknowledged !== true || result.insertedId == null) {
                return createErrorResponse(500, 'contact.save.error', 'Error inserting contact');
            }

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
        let payload = this.jwtUtil.decode(headers.jwtToken);
        let primaryUserId = payload.primaryUserId;
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
                primaryUserId : new ObjectId(primaryUserId),
                type
            };
            if(searchText) {
                query["$or"] = [
                    { name: { $regex: searchText, $options: 'i' } }, // Case-insensitive regex match for contact field
                    { email: { $regex: searchText, $options: 'i' } },    // Case-insensitive regex match for name field
                    { phoneNo: { $regex: searchText, $options: 'i' } }    // Case-insensitive regex match for phone field
                ]
            }

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
        let primaryUserId = payload.primaryUserId;
        const userProfileCol = this.db.collection(USER_PROFILE_COL);
        const userCol = this.db.collection(USER_COL);
        const analyticsCol = this.db.collection(USER_CONTACTS_COL);
        if(!primaryUserId) {
            log.error("primaryUserId should be present in the request");
            return createErrorResponse(400, 'profile.primaryUserId.missing', 'primaryUserId should be present in the request');
        }
        try {
            let query = {
                primaryUserId : new ObjectId(primaryUserId)
            };
            let user = await userProfileCol.findOne(query);
            if(!user){
                log.error(`user not found`);
                return createErrorResponse(404, 'user.not.found', 'User not found by given id');
            }
            let cardsQuery = {
                $or: [
                    { _id: new ObjectId(primaryUserId) }, // Matching documents with _id equal to primaryUserId
                    { primaryUserId: new ObjectId(primaryUserId) } // Matching documents with primaryUserId field equal to primaryUserId
                ],
                isDeleted : 0
            };
            let contactsQuery = {
                ...query,
                type: 'CONTACTS'
            }
            let leadQuery = {
                ...query,
                type: 'LEADS'
            }
            let visitedLinksQuery = {
                ...query,
                type: 'VISITED'
            }
            let [totalCards, totalContacts, totalLeads, totalLinkVisitedTimes] = await Promise.all([
                userCol.countDocuments(cardsQuery),
                analyticsCol.countDocuments(contactsQuery),
                analyticsCol.countDocuments(leadQuery),
                analyticsCol.countDocuments(visitedLinksQuery)
            ]);

            user.totalCards = totalCards;
            user.totalContacts = totalContacts;
            user.totalLeads = totalLeads;
            user.totalLinkVisitedTimes = totalLinkVisitedTimes;

            delete user.password;


            return {
                status: 200,
                content: [user]
            }
        } catch (e) {
            log.error(`error finding user`, e, {});
            return createErrorResponse(500, 'user.profile.find.error', 'Error finding user profile');
        }
    }

    /**
     * Get user by Id
     * @param req
     * @returns {Promise <*>}
     * TYPE-HOME, USERS, REPORTS
     */
    async getDashboardData(req) {
        const { log, headers } = req;
        let { type = 'HOME' } = req.query;
        // here we need to check if it is the admin

        // let payload = this.jwtUtil.decode(headers.jwtToken);
        // console.log("<<<<------------------payload--------------->>>>", payload);
        // let primaryUserId = payload.primaryUserId;
        // console.log("primaryUserId from jwt token", primaryUserId);
        const userProfileCol = this.db.collection(USER_PROFILE_COL);
        const analyticsCol = this.db.collection(USER_CONTACTS_COL);
        const userCol = this.db.collection(USER_COL);

        let result;

        try {

            if(type == 'HOME') {
                let ordersQuery = {
                    type: 'NFC'
                }
                let contactsQuery = {
                    type: 'CONTACTS'
                }
                let leadQuery = {
                    type: 'LEADS'
                }
                let visitedLinksQuery = {
                    type: 'VISITED'
                }
                let aggregateQuery = [{
                        $lookup: {
                            from: USER_COL,
                            localField: "primaryUserId",
                            foreignField: "primaryUserId",
                            as: USER_COL
                        }
                    },
                        {
                            $addFields: {
                                cards: {
                                    $filter: {
                                        input: "$cards",
                                        as: "card",
                                        cond: { $eq: ["$$card.type", "NFC"] } // Filter cards with type NFC
                                    }
                                }
                            }
                        }
                    ]


                let [users, orders, totalLeads, totalContacts, totalLinkVisitedTimes] = await Promise.all([
                    userProfileCol.aggregate(aggregateQuery).toArray(),
                    userCol.find(ordersQuery, {modifiedOn : -1}).toArray(),
                    analyticsCol.countDocuments(leadQuery),
                    analyticsCol.countDocuments(contactsQuery),
                    analyticsCol.countDocuments(visitedLinksQuery)
                ]);

                result = {
                    totalUsers : users.length || 0,
                    totalOrders : orders.length || 0,
                    totalLeads,
                    totalContacts,
                    totalLinkVisitedTimes,
                    users: users,
                    orders : orders

                }

            }

            return {
                status: 200,
                content: result
            }
        } catch (e) {
            log.error(`error finding data`, e, {});
            return createErrorResponse(500, 'data.find.error', 'Error finding data');
        }
    }


    /**
     * Get user by Id
     * @param req
     * @returns {Promise <*>}
     */
    async makePayment(req){
        const { log, headers } = req;
        let { id, primaryUserId, amount, success_url, cancel_url, currency, productName} = req.body;

        if(headers.jwtToken) {
            let payload = this.jwtUtil.decode(headers.jwtToken);
            primaryUserId = payload.primaryUserId;
        }
        const userCol = this.db.collection(USER_COL);
        if(!id || !primaryUserId || !amount || !currency) {
            log.error("All mandatory fields should be present in the request");
            return createErrorResponse(400, 'mandatory.fields.not.present', 'Some of the mandatory fields are not present');
        }
        try {
            let session;
            // Create a PaymentIntent with Stripe
            try {
                session = await stripe.checkout.sessions.create({
                    payment_method_types: ['card'],
                    line_items: [{
                        price_data: {
                            currency: currency,
                            product_data: {
                                name: productName,
                            },
                            unit_amount: amount, // Amount in cents
                        },
                        quantity: 1,
                    }],
                    mode: 'payment',
                    success_url: success_url,
                    cancel_url: cancel_url,
                });

                console.log("session here", session);

            } catch(err) {
                log.error(`error making payment for (id- ${primaryUserId} )`, err, {});
                return createErrorResponse(500, 'stripe.payment.error', 'Error doing payment with stripe');
            }

            let query ={};

            if(primaryUserId) {
                query = {
                    _id: new ObjectId(primaryUserId)
                    // $or: [
                    //     { _id: new ObjectId(primaryUserId) }, // Matching documents with _id equal to primaryUserId
                    //     { primaryUserId: new ObjectId(primaryUserId) } // Matching documents with primaryUserId field equal to primaryUserId
                    // ]
                };
            }

            // query.type = type;
            query.isDeleted = 0;
            let payment = {
                paymentDate :new Date(),
                amount,
                currency,
                productName
            }
            console.log("payment here", payment)
            let updatedUser = userCol.findOneAndUpdate(query, {$set : payment}, { returnDocument: 'after'})
            let updatedNfc = userCol.findOneAndUpdate({_id : new ObjectId(id), isDeleted : 0}, {$set : payment}, { returnDocument: 'after'})
            console.log("updated user here", updatedUser)
            let result = await Promise.all([updatedUser, updatedNfc]);
            console.log("updated result here", result)

            return {
                status: 200,
                content: { id: session.id }
            }

        } catch (e) {
            log.error(`error finding user(id- ${id} )`, e, {});
            return createErrorResponse(500, 'user.find.error', 'Error finding user');
        }
    }


    /**
     * verify Payment
     * @param req
     * @returns {Promise <*>}
     */
    async verifyPayment(req){
        const { log, headers } = req;
        let { id, primaryUserId, sessionId} = req.body;

        if(headers.jwtToken) {
            let payload = this.jwtUtil.decode(headers.jwtToken);
            primaryUserId = payload.primaryUserId;
        }
        const userCol = this.db.collection(USER_COL);
        if(!id || !primaryUserId || !sessionId) {
            log.error("All mandatory fields should be present in the request");
            return createErrorResponse(400, 'mandatory.fields.not.present', 'Some of the mandatory fields are not present');
        }
        try {
            let session, paymentStatus;
            // Create a PaymentIntent with Stripe
            try {
                session = await stripe.checkout.sessions.retrieve(sessionId);

                console.log("session here", session)
                paymentStatus = session.payment_status;
                console.log("session here", session);

            } catch(err) {
                log.error(`error making payment for (id- ${primaryUserId} )`, err, {});
                return createErrorResponse(500, 'stripe.payment.error', 'Error doing payment with stripe');
            }

            let query ={};

            if(primaryUserId) {
                query = {
                    _id: new ObjectId(primaryUserId)
                    // $or: [
                    //     { _id: new ObjectId(primaryUserId) }, // Matching documents with _id equal to primaryUserId
                    //     { primaryUserId: new ObjectId(primaryUserId) } // Matching documents with primaryUserId field equal to primaryUserId
                    // ]
                };
            }

            // query.type = type;
            query.isDeleted = 0;
            let updateQuery = {
                $set : {
                    "payment.status": paymentStatus
                }
            }

            let updatedUser = userCol.findOneAndUpdate(query, updateQuery, { returnDocument: 'after'})
            let updatedNfc = userCol.findOneAndUpdate({_id : new ObjectId(id), isDeleted : 0}, updateQuery, { returnDocument: 'after'})
            console.log("updated user here", updatedUser)
            let result = await Promise.all([updatedUser, updatedNfc]);
            console.log("updated result here", result)

            return {
                status: 200,
                content: 'Updated successfully.'
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