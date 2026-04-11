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

package org.wso2.financial.services.apim.mediation.policies.jws.header.processing.handler.utils;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64URL;
import org.apache.axiom.om.OMElement;
import org.apache.axis2.AxisFault;
import org.apache.axis2.Constants;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.MessageContext;
import org.apache.synapse.SynapseException;
import org.apache.synapse.commons.json.JsonUtil;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.core.axis2.Axis2Sender;
import org.apache.synapse.transport.nhttp.NhttpConstants;
import org.apache.synapse.transport.passthru.PassThroughConstants;
import org.apache.synapse.transport.passthru.util.RelayUtils;
import org.wso2.financial.services.apim.mediation.policies.jws.header.processing.handler.constants.JwsHandlerConstants;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import javax.ws.rs.core.MediaType;
import javax.xml.stream.XMLStreamException;

/**
 * Utility class for handling JWS (JSON Web Signature) related operations in Synapse handlers.
 */
public class JwsHandlerUtils {

    private static final Log log = LogFactory.getLog(JwsHandlerUtils.class);

    /**
     * Return JSON Error for SynapseHandler.
     *
     * @param messageContext messages context.
     * @param code           response code.
     * @param jsonPayload    json payload.
     */
    public static void returnSynapseHandlerJSONError(MessageContext messageContext, String code, String jsonPayload) {

        org.apache.axis2.context.MessageContext axis2MC = ((Axis2MessageContext) messageContext).
                getAxis2MessageContext();
        axis2MC.setProperty(PassThroughConstants.MESSAGE_BUILDER_INVOKED, Boolean.TRUE);
        try {
            RelayUtils.discardRequestMessage(axis2MC);
        } catch (AxisFault axisFault) {
            log.error("Error occurred while discarding the message", axisFault);
        }
        setJsonFaultPayloadToMessageContext(messageContext, jsonPayload);
        sendSynapseHandlerFaultResponse(messageContext, code);
    }

    /**
     * Setting JSON payload as fault message to messageContext.
     * @param messageContext messages context.
     * @param payload json payload.
     */
    private static void setJsonFaultPayloadToMessageContext(MessageContext messageContext, String payload) {

        org.apache.axis2.context.MessageContext axis2MessageContext = ((Axis2MessageContext) messageContext)
                .getAxis2MessageContext();

        axis2MessageContext.setProperty(Constants.Configuration.MESSAGE_TYPE, MediaType.APPLICATION_JSON);

        try {
            JsonUtil.getNewJsonPayload(axis2MessageContext, payload, true, true);
        } catch (AxisFault axisFault) {
            log.error("Unable to set JSON payload to fault message", axisFault);
        }
    }

    /**
     * Send synapseHandler fault response.
     * @param messageContext messages context.
     * @param status error code.
     */
    private static void sendSynapseHandlerFaultResponse(MessageContext messageContext, String status) {

        org.apache.axis2.context.MessageContext axis2MC = ((Axis2MessageContext) messageContext).
                getAxis2MessageContext();

        axis2MC.setProperty(NhttpConstants.HTTP_SC, status);
        messageContext.setResponse(true);
        messageContext.setProperty("RESPONSE", "true");
        messageContext.setTo(null);
        axis2MC.removeProperty(Constants.Configuration.CONTENT_TYPE);
        Axis2Sender.sendBack(messageContext);
    }

    /**
     * Build Message and extract payload.
     *
     * @param axis2MC message context
     * @param headers transport headers
     * @return optional json message
     */
    public static Optional<String> buildMessagePayloadFromMessageContext(
            org.apache.axis2.context.MessageContext axis2MC, Map headers) {

        String requestPayload = null;
        boolean isMessageContextBuilt = isMessageContextBuilt(axis2MC);
        if (!isMessageContextBuilt) {
            // Build Axis2 Message.
            try {
                RelayUtils.buildMessage(axis2MC);
            } catch (IOException | XMLStreamException e) {
                throw new SynapseException("Unable to build axis2 message", e);
            }
        }

        if (headers.containsKey(JwsHandlerConstants.CONTENT_TYPE_TAG)) {
            if (headers.get(JwsHandlerConstants.CONTENT_TYPE_TAG).toString().contains(
                    JwsHandlerConstants.TEXT_XML_CONTENT_TYPE)
                    || headers.get(JwsHandlerConstants.CONTENT_TYPE_TAG).toString().contains(
                    JwsHandlerConstants.APPLICATION_XML_CONTENT_TYPE)
                    || headers.get(JwsHandlerConstants.CONTENT_TYPE_TAG).toString().contains(
                    JwsHandlerConstants.JWT_CONTENT_TYPE)) {

                OMElement payload = axis2MC.getEnvelope().getBody().getFirstElement();
                if (payload != null) {
                    requestPayload = payload.toString();
                } else {
                    requestPayload = "";
                }
            } else {
                // Get JSON Stream and cast to string
                try {
                    InputStream jsonPayload = JsonUtil.getJsonPayload(axis2MC);
                    if (jsonPayload != null) {
                        requestPayload = IOUtils.toString(JsonUtil.getJsonPayload(axis2MC),
                                StandardCharsets.UTF_8.name());
                    }

                } catch (IOException e) {
                    throw new SynapseException("Unable to read payload stream", e);
                }
            }
        }
        return Optional.ofNullable(requestPayload);
    }

    /**
     * Util method to check whether the message context is already built.
     *
     * @param axis2MC axis2 message context
     * @return true if message context is already built
     */
    public static boolean isMessageContextBuilt(org.apache.axis2.context.MessageContext axis2MC) {

        boolean isMessageContextBuilt = false;
        Object messageContextBuilt = axis2MC.getProperty(PassThroughConstants.MESSAGE_BUILDER_INVOKED);
        if (messageContextBuilt != null) {
            isMessageContextBuilt = (Boolean) messageContextBuilt;
        }
        return isMessageContextBuilt;
    }

    /**
     * Constructs a JWS signature with a detached payload.
     *
     * @param payloadString the payload to be signed as a string
     * @param criticalParameters a map of critical parameters to include in the JWS header
     * @param signingKeyId the key ID for the signing key
     * @param signingAlgorithm the JWS signing algorithm to use
     * @param signingCertAlias the alias of the signing certificate in the keystore
     * @return String representing the detached JWS signature
     * @throws JOSEException if there is an error during JWS creation or signing
     */
    public static String constructJWSSignature(String payloadString, HashMap<String, Object> criticalParameters,
                                               String signingKeyId, JWSAlgorithm signingAlgorithm,
                                               String signingCertAlias)
            throws JOSEException {

        String detachedJWS;

        Optional<Key> signingKey;

        // Get signing certificate of ASPSP from keystore
        signingKey = ServerIdentityRetriever.getSigningKey(signingCertAlias);

        if (signingKey.isPresent()) {
            // Create a new JWSSigner
            JWSSigner signer;
            Key privateKey = signingKey.get();

            if (StringUtils.isBlank(signingKeyId)) {
                throw new SynapseException("The kid is not present to sign.");
            }

            JWSHeader jwsHeader = constructJWSHeader(signingKeyId, criticalParameters, signingAlgorithm);
            JWSObject jwsObject = constructJWSObject(jwsHeader, payloadString);

            if ("RSA".equals(privateKey.getAlgorithm())) {
                // If the signing key is an RSA Key
                signer = new RSASSASigner((PrivateKey) privateKey);
            } else if ("EC".equals(privateKey.getAlgorithm())) {
                // If the signing key is an EC Key
                signer = new ECDSASigner((ECPrivateKey) privateKey);
            } else {
                throw new JOSEException("The \"" + privateKey.getAlgorithm() +
                        "\" algorithm is not supported by the Solution");
            }

            try {
                // Check if payload is b64 encoded or un-encoded
                if (isB64HeaderVerifiable(jwsObject)) {
                    // b64=true
                    jwsObject.sign(signer);
                    String serializedJws = jwsObject.serialize();
                    detachedJWS = createDetachedJws(serializedJws);
                } else {
                    // b64=false
                    // Produces the signature with un-encoded payload.
                    // which is the encoded header + ".." + the encoded signature
                    Base64URL signature = signer.sign(jwsHeader, getSigningInput(jwsHeader, payloadString));
                    detachedJWS = createDetachedJws(jwsHeader, signature);
                }
            } catch (JOSEException | UnsupportedEncodingException e) {
                throw new SynapseException("Unable to compute JWS signature", e);
            }
            return detachedJWS;
        } else {
            throw new SynapseException("Signing key is not present");
        }
    }

    /**
     * Returns the JWS Header.
     * @param kid Key id of the signing certificate.
     * @param criticalParameters Hashmap of critical paramters
     * @param algorithm Signing algorithm
     * @return JWSHeader returns Jws Header
     */
    public static JWSHeader constructJWSHeader(String kid, HashMap<String, Object> criticalParameters,
                                               JWSAlgorithm algorithm) {
        return new JWSHeader.Builder(algorithm)
                .keyID(kid)
                .type(JOSEObjectType.JOSE)
                .criticalParams(criticalParameters.keySet())
                .customParams(criticalParameters)
                .build();
    }

    /**
     * Creates a JWS Object
     * @param header JWS header
     * @param responsePayload response payload as a string
     * @return JWSObject jws object created
     */
    public static JWSObject constructJWSObject(JWSHeader header, String responsePayload) {

        return new JWSObject(header, new Payload(responsePayload));
    }

    /**
     * If the b64 header is not available or is true, it is verifiable.
     *
     * @param jwsObject The reconstructed jws object parsed from x-jws-signature
     * @return Boolean
     */
    public static boolean isB64HeaderVerifiable(JWSObject jwsObject) {

        JWSHeader jwsHeader = jwsObject.getHeader();
        Object b64Value = jwsHeader.getCustomParam(JwsHandlerConstants.B64_CLAIM_KEY);
        return b64Value != null ? ((Boolean) b64Value) : true;
    }

    public static String createDetachedJws(String serializedJws) {

        String[] jwsParts = StringUtils.split(serializedJws, ".");
        return jwsParts[0] + ".." + jwsParts[2];
    }

    /**
     * Returns the signing input with encoded jws header and un-encoded payload.
     * @param jwsHeader JWS Header
     * @param payloadString Response payload
     * @return signing input
     * @throws UnsupportedEncodingException throws UnsupportedEncodingException Exception
     */
    public static byte[] getSigningInput(JWSHeader jwsHeader, String payloadString)
            throws UnsupportedEncodingException {

        String combinedInput = jwsHeader.toBase64URL().toString() + "." + payloadString;
        return combinedInput.getBytes(StandardCharsets.UTF_8);
    }

    /**
     *  Method to create a detached jws
     * @param jwsHeader header part of the JWS
     * @param signature signature part of the JWS
     * @return String Detached JWS
     */
    public static String createDetachedJws(JWSHeader jwsHeader, Base64URL signature) {

        return jwsHeader.toBase64URL().toString() + ".." + signature.toString();
    }

}
