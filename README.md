## RSA Signing a request in Ballerina

Sign an http request using RSA SHA256 algorithm and returns the authorization header. As of now only GET requests are supported and SHA256 algorithm.

Call the function *crypto:rsa* by passing request URI, path to the private key (.pem), api key id, "GET", "SHA256".

This is tested with Ballerina 0.990.0 source code

Copy Rsa.java to the below location:
<BAL_SOURCE>/stdlib/crypto/src/main/java/org/ballerinalang/stdlib/crypto/nativeimpl

Copy natives.bal to the below location:
<BAL_SOURCE>/stdlib/crypto/src/main/ballerina/crypto

Copy pom_main.bal to the <BAL_SOURCE> root folder (i.e. ballerina-lang) and rename it to pom.xml

Copy pom_crypto.bal to the below location and rename it to pom.xml:
<BAL_SOURCE>/stdlib/crypto

Copy bin.xml to the below location:
<BAL_SOURCE>/distribution/zip/ballerina/src/assembly

Build ballerina. Extract the ballerina distribution and call the function.

Use ListInstance.bal example to list all compute instances in a compartment on Oracle Cloud
