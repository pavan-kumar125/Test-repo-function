import { app, HttpRequest, HttpResponseInit, InvocationContext } from "@azure/functions";
import { ManagedIdentityCredential } from "@azure/identity";
import {
    STSClient,
    AssumeRoleWithWebIdentityCommand,
} from "@aws-sdk/client-sts";
import { CognitoJwtVerifier } from "aws-jwt-verify";

// const audience = process.env.AUDIENCE;
// const roleArn = process.env.ROLE_ARN;
// const region = process.env.REGION;

// import { StopViewSession } from "amutri-client-common";

// const verifier = CognitoJwtVerifier.create({
//     userPoolId: process.env.COGNITO_USER_POOL_ID || "",
//     tokenUse: "access",
//     clientId: process.env.COGNITO_CLIENT_ID || "",
// });

export async function stopViewSession(request: HttpRequest, context: InvocationContext): Promise<HttpResponseInit> {
    try {
        context.log("stopViewSession from azure is called");
        context.log(`Http function processed request for url "${request.url}"`);

        // const request_body = request.method === "POST"
        //     ? await request.json()
        //     : Object.fromEntries(request.query.entries());

        // context.log({ request_body });

        // console.log = function () {
        //     context.log.apply(context, arguments);
        // };

        // // check authorization
        // const headers = Object.fromEntries(request.headers.entries());
        // context.log("All Headers:", headers);
        // const cognitoAuthToken = request.headers.get("authorization");
        // if (!cognitoAuthToken) {
        //     throw new Error("Missing authorization token in headers.");
        // }
        // const payload = await verifier.verify(cognitoAuthToken);
        // context.log("Token is valid. Payload:", payload);

        // // coustomize the request
        // const event = {
        //     "arguments": request_body,
        //     "identity": {
        //         "claims": payload
        //     }
        // }
        // context.log("event", event)

        // // Creating the credentials
        // const credential = new ManagedIdentityCredential(
        //     process.env.AWS_DELEGATION_ID // ClientID of user-delegation--id-8df8
        // );

        // // Get token for the specified audience
        // const tokenResponse = await credential.getToken(audience);
        // const accessToken = tokenResponse.token;

        // // Assume AWS Role using STS
        // const stsClient = new STSClient({ region });

        // const assumeRoleCommand = new AssumeRoleWithWebIdentityCommand({
        //     RoleArn: roleArn,
        //     WebIdentityToken: accessToken,
        //     RoleSessionName: "AzureFunctionSession",
        // });

        // const assumeRoleResponse = await stsClient.send(assumeRoleCommand);
        // const credentials = assumeRoleResponse.Credentials;

        // if (!credentials) {
        //     throw new Error("Failed to obtain AWS credentials");
        // }

        // // Call the ManageStartViewSession function
        // const awsCredentials = {
        //     accessKeyId: credentials.AccessKeyId,
        //     secretAccessKey: credentials.SecretAccessKey,
        //     sessionToken: credentials.SessionToken,
        // };

        // await StopViewSession(sessionInfo, awsCredentials);

        // Constructing the response
        const response: HttpResponseInit = {
            status: 200,
            body: "Stopping session successfully",
        };

        return response;
    } catch (error) {
        context.error("An error occurred:", error);
        return {
            status: 500,
            body: `An error occurred: ${error.message}`,
        };
    }
};

app.http('stopViewSession', {
    methods: ['GET', 'POST'],
    authLevel: 'anonymous',
    handler: stopViewSession
});
