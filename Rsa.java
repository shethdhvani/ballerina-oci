/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.ballerinalang.stdlib.crypto.nativeimpl;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.hash.Hashing;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpEntityEnclosingRequestBase;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;

import org.ballerinalang.bre.Context;
import org.ballerinalang.bre.bvm.BlockingNativeCallableUnit;
import org.ballerinalang.model.types.TypeKind;
import org.ballerinalang.model.values.BString;
import org.ballerinalang.model.values.BValue;
import org.ballerinalang.natives.annotations.Argument;
import org.ballerinalang.natives.annotations.BallerinaFunction;
import org.ballerinalang.natives.annotations.ReturnType;
import org.ballerinalang.util.exceptions.BallerinaException;

import org.tomitribe.auth.signatures.MissingRequiredHeaderException;
import org.tomitribe.auth.signatures.PEM;
import org.tomitribe.auth.signatures.Signature;
import org.tomitribe.auth.signatures.Signer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TimeZone;
import java.util.stream.Collectors;


/**
 * Extern function ballerina.crypto:getRsa.
 *
 * @since 0.990.0
 */

 /**
 * This example creates a {@link RequestSigner}, then prints out the Authorization header
 * that is inserted into the HttpGet object.
 *
 * <p>
 * apiKey is the identifier for a key uploaded through the console.
 * privateKeyFilename is the location of your private key (that matches the uploaded public key for apiKey).
 * </p>
 *
 * The signed HttpGet request is not executed, since instanceId does not map to a real instance.
 */
@BallerinaFunction(
        orgName = "ballerina", packageName = "crypto",
        functionName = "rsa",
        args = {
                @Argument(name = "uriString", type = TypeKind.STRING),
                @Argument(name = "privateKeyPath", type = TypeKind.STRING),
                @Argument(name = "apiKey", type = TypeKind.STRING),
                @Argument(name = "method", type = TypeKind.STRING),
                @Argument(name = "keyEncoding", type = TypeKind.STRING),
                @Argument(name = "algorithm", type = TypeKind.STRING),
        },
        returnType = {@ReturnType(type = TypeKind.STRING)},
        isPublic = true
)
public class Rsa extends BlockingNativeCallableUnit {

    @Override
    public void execute(Context context) {
        String uriString = context.getStringArgument(0);
        String privateKeyPath = context.getStringArgument(1);
        BString algorithm = context.getNullableRefArgument(0) != null ?
            (BString) context.getNullableRefArgument(0) : new BString("");
        BValue encodingBVal = context.getNullableRefArgument(1);
        String encoding = encodingBVal != null ? encodingBVal.stringValue() : "UTF-8";
        String apiKey = context.getStringArgument(2);
        String method = context.getStringArgument(3);

        String rsaAlgorithm;

        //todo document the supported algorithm
        switch (algorithm.stringValue()) {
            case "SHA256":
                rsaAlgorithm = "SHA256withRSA";
                break;
            default:
                throw new BallerinaException("Unsupported algorithm " + algorithm + " for RSA calculation");
        }

        String result;

        HttpRequestBase request;

        String responseString;

        switch (method) {
            case "GET":
                try {
        
                    PrivateKey privateKey = loadPrivateKey(privateKeyPath);
                    RequestSigner signer = new RequestSigner(apiKey, privateKey);
        
                    request = new HttpGet(uriString);
                    signer.signRequest(request);
                    @SuppressWarnings({ "deprecation", "resource" })
                    HttpClient client = new DefaultHttpClient();
                    HttpResponse httpResponse = client.execute(request);
                    HttpEntity entity = httpResponse.getEntity();
                    responseString = EntityUtils.toString(entity, "UTF-8");
        
                } catch (IllegalArgumentException | IOException e) {
                    throw new BallerinaException("Error while calculating RSA for " + 
                        rsaAlgorithm + ": " + e.getMessage(), context);
                }
                break;
            default:
                throw new BallerinaException("Unsupported HTTP Request method " + method + " for RSA calculation");
        }
        context.setReturnValues(new BString(responseString));
    }

    /**
     * Load a {@link PrivateKey} from a file.
     */
    private static PrivateKey loadPrivateKey(String privateKeyFilename) {
        try (InputStream privateKeyStream = Files.newInputStream(Paths.get(privateKeyFilename))) {
            return PEM.readPrivateKey(privateKeyStream);
        } catch (InvalidKeySpecException e) {
                throw new RuntimeException("Invalid format for private key");
        } catch (IOException e) {
            throw new RuntimeException("Failed to load private key");
        }
    }

    /**
     * A light wrapper around https://github.com/tomitribe/http-signatures-java
     */
    public static class RequestSigner {
        private static final SimpleDateFormat DATE_FORMAT;
        private static final String SIGNATURE_ALGORITHM = "rsa-sha256";
        private static final Map<String, List<String>> REQUIRED_HEADERS;
        static {
            DATE_FORMAT = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz", Locale.US);
            DATE_FORMAT.setTimeZone(TimeZone.getTimeZone("GMT"));
            REQUIRED_HEADERS = ImmutableMap.<String, List<String>>builder()
                    .put("get", ImmutableList.of("date", "(request-target)", "host"))
                    .put("head", ImmutableList.of("date", "(request-target)", "host"))
                    .put("delete", ImmutableList.of("date", "(request-target)", "host"))
                    .put("put", ImmutableList.of("date", "(request-target)", "host", "content-length", 
                        "content-type", "x-content-sha256"))
                    .put("post", ImmutableList.of("date", "(request-target)", "host", "content-length", 
                        "content-type", "x-content-sha256"))
            .build();
        }
        private final Map<Object, Object> signers;

        /**
         * @param apiKey The identifier for a key uploaded through the console.
         * @param privateKey The private key that matches the uploaded public key for the given apiKey.
         */
        public RequestSigner(String apiKey, Key privateKey) {
            this.signers = REQUIRED_HEADERS
                    .entrySet().stream()
                    .collect(Collectors.toMap(
                            entry -> entry.getKey(),
                            entry -> buildSigner(apiKey, privateKey, entry.getKey())));
        }

        /**
         * Create a {@link Signer} that expects the headers for a given method.
         * @param apiKey The identifier for a key uploaded through the console.
         * @param privateKey The private key that matches the uploaded public key for the given apiKey.
         * @param method HTTP verb for this signer
         * @return Signer
         */
        protected Signer buildSigner(String apiKey, Key privateKey, String method) {
            final Signature signature = new Signature(
                    apiKey, SIGNATURE_ALGORITHM, null, REQUIRED_HEADERS.get(method.toLowerCase(Locale.ENGLISH)));
            return new Signer(privateKey, signature);
        }

        /**
         * Sign a request, optionally including additional headers in the signature.
         *
         * <ol>
         * <li>If missing, insert the Date header (RFC 2822).</li>
         * <li>If PUT or POST, insert any missing content-type, content-length, x-content-sha256</li>
         * <li>Verify that all headers to be signed are present.</li>
         * <li>Set the request's Authorization header to the computed signature.</li>
         * </ol>
         *
         * @param request The request to sign
         */
        public void signRequest(HttpRequestBase request) {
            final String method = request.getMethod().toLowerCase(Locale.ENGLISH);
            // nothing to sign for options
            if (method.equals("options")) {
                return;
            }

            final String path = extractPath(request.getURI());

            // supply date if missing
            if (!request.containsHeader("date")) {
                final SimpleDateFormat simpleDateFormat;
                simpleDateFormat = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz", Locale.US);
                simpleDateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
                request.addHeader("date", simpleDateFormat.format(new Date()));
            }

            // supply host if mossing
            if (!request.containsHeader("host")) {
                request.addHeader("host", request.getURI().getHost());
            }

            // supply content-type, content-length, and x-content-sha256 if missing (PUT and POST only)
            if (method.equals("put") || method.equals("post")) {
                if (!request.containsHeader("content-type")) {
                    request.addHeader("content-type", "application/json");
                }
                if (!request.containsHeader("content-length") || !request.containsHeader("x-content-sha256")) {
                    assert request instanceof HttpEntityEnclosingRequestBase : request.getClass();
                    byte[] body = getRequestBody((HttpEntityEnclosingRequestBase) request);
                    if (!request.containsHeader("content-length")) {
                        request.addHeader("content-length", Integer.toString(body.length));
                    }
                    if (!request.containsHeader("x-content-sha256")) {
                        request.addHeader("x-content-sha256", calculateSHA256(body));
                    }
                }
            }

            final Map<String, String> headers = extractHeadersToSign(request);
            final String signature = this.calculateSignature(method, path, headers);
            request.setHeader("Authorization", signature);
        }

        /**
         * Extract path and query string to build the (request-target) pseudo-header.
         * For the URI "http://www.host.com/somePath?example=path" return "/somePath?example=path"
         */
        private static String extractPath(URI uri) {
            String path = uri.getRawPath();
            String query = uri.getRawQuery();
            if (query != null && !query.trim().isEmpty()) {
                path = path + "?" + query;
            }
            return path;
        }

        /**
         * Extract the headers required for signing from a {@link HttpRequestBase}, into a Map
         * that can be passed to {@link RequestSigner#calculateSignature}.
         *
         * <p>
         * Throws if a required header is missing, or if there are multiple values for a single header.
         * </p>
         *
         * @param request The request to extract headers from.
         */
        private static Map<String, String> extractHeadersToSign(HttpRequestBase request) {
            List<String> headersToSign = REQUIRED_HEADERS.get(request.getMethod().toLowerCase(Locale.ENGLISH));
            if (headersToSign == null) {
                throw new RuntimeException("Don't know how to sign method " + request.getMethod());
            }
            return headersToSign.stream()
                    // (request-target) is a pseudo-header
                    .filter(header -> !header.toLowerCase(Locale.ENGLISH).equals("(request-target)"))
                    .collect(Collectors.toMap(
                    header -> header,
                    header -> {
                        if (!request.containsHeader(header)) {
                            throw new MissingRequiredHeaderException(header);
                        }
                        if (request.getHeaders(header).length > 1) {
                            throw new RuntimeException(
                                    String.format("Expected one value for header %s", header));
                        }
                        return request.getFirstHeader(header).getValue();
                    }));
        }

        /**
         * Wrapper around {@link Signer#sign}, returns the {@link Signature} as a String.
         *
         * @param method Request method (GET, POST, ...)
         * @param path The path + query string for forming the (request-target) pseudo-header
         * @param headers Headers to include in the signature.
         */
        private String calculateSignature(String method, String path, Map<String, String> headers) {
            Signer signer = (Signer) this.signers.get(method);
            if (signer == null) {
                throw new RuntimeException("Don't know how to sign method " + method);
            }
            try {
                return signer.sign(method, path, headers).toString();
            } catch (IOException e) {
                throw new RuntimeException("Failed to generate signature", e);
            }
        }

        /**
         * Calculate the Base64-encoded string representing the SHA256 of a request body.
         * @param body The request body to hash
         */
        private String calculateSHA256(byte[] body) {
            byte[] hash = Hashing.sha256().hashBytes(body).asBytes();
            return Base64.getEncoder().encodeToString(hash);
        }

        /**
         * Helper to safely extract a request body.  Because an {@link HttpEntity} may not be repeatable,
         * this function ensures the entity is reset after reading.  Null entities are treated as an empty string.
         *
         * @param request A request with a (possibly null) {@link HttpEntity}
         */
        private byte[] getRequestBody(HttpEntityEnclosingRequestBase request) {
            HttpEntity entity = request.getEntity();
            // null body is equivalent to an empty string
            if (entity == null) {
                return "".getBytes(StandardCharsets.UTF_8);
            }
            // May need to replace the request entity after consuming
            boolean consumed = !entity.isRepeatable();
            ByteArrayOutputStream content = new ByteArrayOutputStream();
            try {
                entity.writeTo(content);
            } catch (IOException e) {
                throw new RuntimeException("Failed to copy request body", e);
            }
            // Replace the now-consumed body with a copy of the content stream
            byte[] body = content.toByteArray();
            if (consumed) {
                request.setEntity(new ByteArrayEntity(body));
            }
            return body;
        }
    }

}



    
