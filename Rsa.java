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

package main.java.org.ballerinalang.stdlib.crypto.nativeimpl;

import org.ballerinalang.bre.Context;
import org.ballerinalang.bre.bvm.BlockingNativeCallableUnit;
import org.ballerinalang.model.types.TypeKind;
import org.ballerinalang.model.values.BString;
import org.ballerinalang.model.values.BValue;
import org.ballerinalang.natives.annotations.Argument;
import org.ballerinalang.natives.annotations.BallerinaFunction;
import org.ballerinalang.natives.annotations.ReturnType;
import org.ballerinalang.util.exceptions.BallerinaException;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;


/**
 * Extern function ballerina.crypto:getRsa.
 *
 * @since 0.990.0
 */
@BallerinaFunction(
        orgName = "ballerina", packageName = "crypto",
        functionName = "rsa",
        args = {
                @Argument(name = "signingString", type = TypeKind.STRING),
                @Argument(name = "privateKeyPath", type = TypeKind.STRING),
                @Argument(name = "keyEncoding", type = TypeKind.STRING),
                @Argument(name = "algorithm", type = TypeKind.STRING)
        },
        returnType = {@ReturnType(type = TypeKind.STRING)},
        isPublic = true
)
public class Rsa extends BlockingNativeCallableUnit {

    @Override
    public void execute(Context context) {
        String signingString = context.getStringArgument(0);
        String privateKeyPath = context.getStringArgument(1);
        BString algorithm = context.getNullableRefArgument(0) != null ?
                (BString) context.getNullableRefArgument(0) : new BString("");
        BValue encodingBVal = context.getNullableRefArgument(1);
        String encoding = encodingBVal != null ? encodingBVal.stringValue() : "UTF-8";

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

        try {
            // Generate Signature object with signing algorithm and provider(?)
            Signature rsa = Signature.getInstance(rsaAlgorithm);

            String privateKeyContent = new String(Files.readAllBytes(Paths.get(ClassLoader.
                getSystemResource(privateKeyPath).toURI())), "UTF-8");

            privateKeyContent = privateKeyContent.replaceAll("\\n", "").replace("-----BEGIN PRIVATE KEY-----", "").
                replace("-----END PRIVATE KEY-----", "");

            KeyFactory kf = KeyFactory.getInstance("RSA");

            PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent));
            PrivateKey privKey = kf.generatePrivate(keySpecPKCS8);

            // Initialize newly created signature with our private key
            rsa.initSign(privKey);

            byte[] b = signingString.getBytes(StandardCharsets.UTF_8); // Java 7+ only
            rsa.update(b);

            // Once all of the data has been supplied to the object, it can be signed
            byte[] realSig = rsa.sign();

            // convert the byte[] to string
            result = Arrays.toString(realSig);


        } catch (IllegalArgumentException | InvalidKeyException | NoSuchAlgorithmException | 
            URISyntaxException | IOException | InvalidKeySpecException | SignatureException e) {
            throw new BallerinaException("Error while calculating RSA for " + rsaAlgorithm + ": " + e.getMessage(),
                    context);
        }
        context.setReturnValues(new BString(result));
    }
}

