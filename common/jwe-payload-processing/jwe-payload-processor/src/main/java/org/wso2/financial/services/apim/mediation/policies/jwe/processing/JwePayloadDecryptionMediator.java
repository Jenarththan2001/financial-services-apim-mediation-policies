/**
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
 * <p>
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 *     http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.financial.services.apim.mediation.policies.jwe.processing;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.MessageContext;
import org.apache.synapse.SynapseException;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.mediators.AbstractMediator;
import org.json.JSONObject;
import org.wso2.financial.services.apim.mediation.policies.jwe.processing.exceptions.JwePayloadProcessingException;
import org.wso2.financial.services.apim.mediation.policies.jwe.processing.util.HsmJweDecryptionHelper;
import org.wso2.financial.services.apim.mediation.policies.jwe.processing.util.JwePayloadProcessingUtils;
import org.wso2.financial.services.apim.mediation.policies.jwe.processing.util.ServerKeystoreRetriever;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PrivateKey;
import java.text.ParseException;
import java.util.Map;
import java.util.Optional;

/**
 * Mediator to decrypt the JWE encrypted payload in the request.
 */
public class JwePayloadDecryptionMediator extends AbstractMediator {

    private static final Log log = LogFactory.getLog(JwePayloadDecryptionMediator.class);
    private String jweEncryptionCertAlias = null;

    /**
     * Method to decrypt the JWE encrypted payload in the request and set the decrypted payload back to the message.
     * The method will check the content-type of the request payload and if it is a supported content-type
     * (application/jose+jwe), it will proceed with the decryption. In the decryption, it will use the private key of
     * the server keystore to decrypt the payload.
     * <p>
     * This implementation supports only "RSA-OAEP-256", "RSA-OAEP", "RSA-OAEP-384", "RSA-OAEP-512" and "RSA1_5" as
     * encryption algorithms and "A128GCM", "A256GCM" and "A192GCM" as encryption methods.
     *
     * @param messageContext the message context
     * @return true if the mediation is successful, false otherwise
     */
    @Override
    public boolean mediate(MessageContext messageContext) {

        org.apache.axis2.context.MessageContext axis2MessageContext =
                ((Axis2MessageContext) messageContext).getAxis2MessageContext();
        Map<String, Object> headers = (Map<String, Object>) axis2MessageContext
                .getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);

        String contentType = JwePayloadProcessingUtils.getContentType(headers);
        // If the content-type of the request payload is not supported or if the content-type is null or empty,
        // the handler will not perform the payload decryption.
        if (!JwePayloadProcessingUtils.isSupportedContentType(contentType)) {
            if (log.isDebugEnabled()) {
                log.debug("Payload decrypted is skipped as the Content-Type: " + contentType
                        + " is not supported by the " + JwePayloadDecryptionMediator.class.getName() +
                        ". Currently, the supported Content types are " +
                        JwePayloadProcessingUtils.getSupportedContentTypes());
            }
            return true;
        }

        try {
            // Extract the payload from the message context as a base64 encoded string
            Optional<String> encryptedPayload = JwePayloadProcessingUtils.buildMessagePayloadFromMessageContext(
                    axis2MessageContext, contentType);

            // If the payload is empty, skip the decryption
            if (!encryptedPayload.isPresent()) {
                if (log.isDebugEnabled()) {
                    log.debug("Payload decryption is skipped as the payload is empty.");
                }
                return true;
            }

            // Get the private key of the server certificates from the keystore to decrypt the payload
            ServerKeystoreRetriever keystoreRetriever = ServerKeystoreRetriever.getInstance();
            Key privateKey = keystoreRetriever.getSigningKey(getJweEncryptionCertAlias());
            if (privateKey == null) {
                log.error("Private key not found in the keystore. Hence, cannot proceed with payload decryption.");
                throw new SynapseException("Error occurred while payload decryption.");
            }

            // Decrypt the token
            EncryptedJWT parsedJwt = EncryptedJWT.parse(encryptedPayload.get());
            JWTClaimsSet decryptedClaimsSet;

            if (keystoreRetriever.isHSMEnabled()) {
                // HSM path: SunPKCS11 does not support RSA-OAEP Cipher padding, so we bypass
                // Nimbus RSADecrypter and perform raw RSA in HSM + manual OAEP unpadding + AES-GCM
                log.info("HSM enabled: Using custom JWE decryption (raw RSA in HSM + OAEP unpad).");
                decryptedClaimsSet = HsmJweDecryptionHelper.decryptWithHSM(parsedJwt, (PrivateKey) privateKey);
            } else {
                // Standard path: Use Nimbus RSADecrypter (original behavior)
                RSADecrypter decrypter = new RSADecrypter((PrivateKey) privateKey);
                parsedJwt.decrypt(decrypter);
                decryptedClaimsSet = parsedJwt.getJWTClaimsSet();
            }
            if (log.isDebugEnabled()) {
                log.debug("Decrypted JWT Claims: " + decryptedClaimsSet.toString());
            }

            // Set the decrypted payload back to the message context
            JSONObject payloadObj = new JSONObject(decryptedClaimsSet.toString());
            JwePayloadProcessingUtils.setDecryptedPayloadToMessageContext(messageContext, payloadObj, headers);

        } catch (JwePayloadProcessingException e) {
            log.error(e.getMessage(), e);
            throw new SynapseException(e.getMessage(), e);
        } catch (ParseException | JOSEException e) {
            log.error("Error while parsing/decrypting the JWE token", e);
            throw new SynapseException("Error while parsing/decrypting the JWE token", e);
        } catch (GeneralSecurityException e) {
            log.error("Error during HSM JWE decryption", e);
            throw new SynapseException("Error during HSM JWE decryption", e);
        }
        return true;
    }

    public void setJweEncryptionCertAlias(String jweEncryptionCertAlias) {
        this.jweEncryptionCertAlias = jweEncryptionCertAlias;
    }

    public String getJweEncryptionCertAlias() {
        return jweEncryptionCertAlias;
    }
}
