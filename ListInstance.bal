import ballerina/http;
import ballerina/io;
import ballerina/time;
import ballerina/system;
import ballerina/crypto;
import ballerina/file;
import ballerina/log;
import ballerina/mime;

http:Client clientEndpoint = new("https://iaas.us-ashburn-1.oraclecloud.com");

function checkEncode(string str) returns string|error {
    string resultStr = check http:encode(str, "UTF-8");
    return resultStr;
}

public function main() {
    string compartmentId = <YOUR COMPARTMENT ID>;
    http:Request request = new;
    string date;
    time:Time time = time:currentTime().toTimezone("GMT");
    date = time.format("E, dd MMM yyyy HH:mm:ss") + " GMT";
    request.setHeader("date", date);
    string partReqTarget = "get /20160918/instances/?compartmentId=";
    var value = http:encode(compartmentId, "UTF-8");
    string encodedString;
    if (value is string) {
        encodedString = value;
    } else {
        error err = error("100", { message: "Error occurred when converting to int"});
        panic err;
    }
    string requestURI = "/20160918/instances/?compartmentId=" + encodedString;
    string reqTarget = partReqTarget + encodedString;
    request.setHeader("request-target", reqTarget);
    string host = "iaas.us-ashburn-1.oraclecloud.com";
    request.setHeader("host", host);

    // api key id
    string tenancyId= <YOUR TENANCY ID>;
    string authUserId= <YOUR USER ID>;
    string keyFingerprint = <YOUR FINGERPRINT ID>; 
    string apiKeyId = tenancyId + "/" + authUserId + "/" + keyFingerprint;

    string pathToKey = <YOUR PATH TO PRIVATE KEY>;

    string uriString = "https://iaas.us-ashburn-1.oraclecloud.com" + requestURI;
    
    string authHeader = crypto:rsa(uriString, pathToKey, apiKeyId, "GET", "SHA256");

    io:println("authHeader from RSA: ", authHeader);

    authHeader = authHeader.replace("Authorization: ", "");

    request.setHeader("Authorization", authHeader);

    // Send a GET request to the specified endpoint.
    var response = clientEndpoint->get(requestURI, message = request);

    if (response is http:Response) {
        io:println("GET request:");
        var msg = response.getJsonPayload();
        if (msg is json) {
            io:println(msg);
        } else {
            log:printError("Invalid payload received", err = msg);
        }
    } else {
        log:printError("Error when calling the backend", err = response);
    }
    
}


