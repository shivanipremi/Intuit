/**
 * Configuration for partner logic.
 */
module.exports = {
    'default': {
        objectId: {
            type: "string",
            pattern: "^[0-9A-Fa-f]{24}$"
        },
        securityQuestion: {
            properties: {
                id: { type: "number" },
                answer: { type: "string" }
            },
            required: ["id", "answer"]
        },
        CardPost: {
            properties: {
                name: { type: "string" },
                countryCode : { type: "string" },
                phoneNo: {type: "string"},
                email: { type: "string", pattern: "^\\S+@\\S+\\.\\S+$"},
                profilePicURL: {type: "string"},
                logoURL: {type: "string"}
            },
            required: ['name', 'email', 'countryCode', 'phoneNo'],
            // Accept properties not the list
            additionalProperties: true
        },
        CardUpdate: {
            properties: {
                primaryUserId: { type: "string" }
            },
            required: ['name', 'email', 'countryCode', 'phoneNo'],
            // Accept properties not the list
            additionalProperties: true
        },
        UserPasswordReset: {
            properties: {
                loginId: { type: "string", minLength: 6 },
                securityQuestions: {
                    type: "array",
                    items: { "$ref": "securityQuestion" },
                    minItems: 1
                },
                password: { type: "string", minLength: 8, pattern: ".{8,}$" },
                supportEmail: { type: "string" },
            },
            required: ['loginId', 'securityQuestions', 'password'],
            additionalProperties: false
        },
        UserLogin: {
            properties: {
                loginId: { type: "string", minLength: 6 },
                password: { type: "string"},
            },
            required: ["loginId", "password"],
            additionalProperties: true
        },
        UserConfirmEmail: {
            properties: {
                loginId: { type: "string", minLength: 6 },
                token: { type: "string", pattern: "^[A-Za-z0-9]{8}"}
            },
            required : ['loginId', 'token'],
            additionalProperties: false
        }
    }
};