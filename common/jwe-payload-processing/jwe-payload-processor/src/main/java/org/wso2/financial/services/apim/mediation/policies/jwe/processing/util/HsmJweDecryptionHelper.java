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

package org.wso2.financial.services.apim.mediation.policies.jwe.processing.util;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.text.ParseException;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * HSM-aware JWE decryption helper.
 * <p>
 * SunPKCS11 does not support RSA-OAEP Cipher padding, so Nimbus RSADecrypter fails with
 * HSM-backed P11PrivateKey. This helper bypasses Nimbus and performs JWE decryption manually:
 * <ol>
 *   <li>Raw RSA decrypt inside HSM (RSA/ECB/NoPadding via SunPKCS11) - private key never leaves HSM</li>
 *   <li>OAEP unpadding in software (RFC 3447 Section 7.1.2) - no secret material needed</li>
 *   <li>AES-GCM content decryption with recovered CEK</li>
 * </ol>
 * <p>
 * Supports RSA-OAEP-256, RSA-OAEP, RSA-OAEP-384, RSA-OAEP-512 and RSA1_5 key encryption
 * with A128GCM / A192GCM / A256GCM content encryption.
 */
public class HsmJweDecryptionHelper {

    private static final Log log = LogFactory.getLog(HsmJweDecryptionHelper.class);

    private static final int GCM_TAG_BIT_LENGTH = 128;

    /**
     * Decrypt a JWE token using an HSM-backed private key.
     * Finds the SunPKCS11 provider automatically based on the key type.
     *
     * @param parsedJwt  The parsed EncryptedJWT to decrypt
     * @param privateKey The HSM-backed private key (P11PrivateKey)
     * @return The decrypted JWT claims
     * @throws GeneralSecurityException if any cryptographic operation fails
     * @throws ParseException           if the decrypted payload cannot be parsed as JWT claims
     */
    public static JWTClaimsSet decryptWithHSM(EncryptedJWT parsedJwt, PrivateKey privateKey)
            throws GeneralSecurityException, ParseException {

        // Find the SunPKCS11 provider
        Provider hsmProvider = getHSMProvider(privateKey);
        if (hsmProvider == null) {
            throw new GeneralSecurityException(
                    "Could not find SunPKCS11 provider for HSM JWE decryption. Key type: "
                            + privateKey.getClass().getName());
        }

        return decryptWithHSM(parsedJwt, privateKey, hsmProvider);
    }

    /**
     * Decrypt a JWE token using the given private key and RSA provider.
     * Package-private for testability — allows unit tests to provide a standard Java RSA provider
     * instead of requiring a real PKCS#11 HSM.
     *
     * @param parsedJwt   The parsed EncryptedJWT to decrypt
     * @param privateKey  The private key for RSA decryption
     * @param rsaProvider The security provider for RSA Cipher operations
     * @return The decrypted JWT claims
     * @throws GeneralSecurityException if any cryptographic operation fails
     * @throws ParseException           if the decrypted payload cannot be parsed as JWT claims
     */
    static JWTClaimsSet decryptWithHSM(EncryptedJWT parsedJwt, PrivateKey privateKey, Provider rsaProvider)
            throws GeneralSecurityException, ParseException {

        JWEHeader header = parsedJwt.getHeader();
        JWEAlgorithm algorithm = header.getAlgorithm();
        EncryptionMethod encMethod = header.getEncryptionMethod();

        // Validate supported algorithms
        validateAlgorithm(algorithm, encMethod);

        // Extract JWE components
        byte[] encryptedCEK = parsedJwt.getEncryptedKey().decode();
        byte[] iv = parsedJwt.getIV().decode();
        byte[] cipherText = parsedJwt.getCipherText().decode();
        byte[] authTag = parsedJwt.getAuthTag().decode();
        byte[] aad = header.toBase64URL().toString().getBytes(StandardCharsets.US_ASCII);

        if (log.isDebugEnabled()) {
            log.debug("HSM JWE decrypt: algo=" + algorithm + ", enc=" + encMethod
                    + ", provider=" + rsaProvider.getName());
        }

        // Unwrap the CEK using the appropriate RSA padding scheme
        byte[] cekBytes;

        if (JWEAlgorithm.RSA1_5.equals(algorithm)) {
            // RSA1_5 uses PKCS#1 v1.5 padding — supported directly
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", rsaProvider);
            rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
            cekBytes = rsaCipher.doFinal(encryptedCEK);
        } else {
            // RSA-OAEP variants: raw RSA + manual OAEP unpadding in software
            String oaepHashAlgo = getOAEPHashAlgorithm(algorithm);

            // Step 1: Raw RSA decrypt (in production, the private key stays inside the HSM)
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/NoPadding", rsaProvider);
            rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] rawDecrypted = rsaCipher.doFinal(encryptedCEK);

            // Step 2: Manual OAEP unpadding in software (RFC 3447 Section 7.1.2)
            // Use encryptedCEK.length for key size — RSA ciphertext is always exactly the modulus size.
            // rawDecrypted.length may be shorter if SunPKCS11 strips leading zero bytes.
            int keyBitLength = encryptedCEK.length * 8;
            cekBytes = oaepUnpad(rawDecrypted, oaepHashAlgo, keyBitLength);
        }

        // Step 3: AES-GCM content decryption with recovered CEK
        byte[] gcmInput = new byte[cipherText.length + authTag.length];
        System.arraycopy(cipherText, 0, gcmInput, 0, cipherText.length);
        System.arraycopy(authTag, 0, gcmInput, cipherText.length, authTag.length);

        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_BIT_LENGTH, iv);
        SecretKeySpec cekKey = new SecretKeySpec(cekBytes, "AES");
        aesCipher.init(Cipher.DECRYPT_MODE, cekKey, gcmSpec);
        aesCipher.updateAAD(aad);
        byte[] plaintext = aesCipher.doFinal(gcmInput);

        String payloadJson = new String(plaintext, StandardCharsets.UTF_8);
        if (log.isDebugEnabled()) {
            log.debug("HSM JWE decryption successful.");
        }

        return JWTClaimsSet.parse(payloadJson);
    }

    /**
     * Validate that the JWE algorithm and encryption method are supported.
     */
    static void validateAlgorithm(JWEAlgorithm algorithm, EncryptionMethod encMethod)
            throws GeneralSecurityException {

        // Supported key encryption algorithms
        if (!JWEAlgorithm.RSA_OAEP_256.equals(algorithm)
                && !JWEAlgorithm.RSA_OAEP.equals(algorithm)
                && !JWEAlgorithm.RSA_OAEP_384.equals(algorithm)
                && !JWEAlgorithm.RSA_OAEP_512.equals(algorithm)
                && !JWEAlgorithm.RSA1_5.equals(algorithm)) {
            throw new GeneralSecurityException(
                    "Unsupported JWE key encryption algorithm for HSM: " + algorithm
                            + ". Supported: RSA-OAEP-256, RSA-OAEP, RSA-OAEP-384, RSA-OAEP-512, RSA1_5");
        }

        // Supported content encryption methods (AES-GCM variants)
        if (!EncryptionMethod.A256GCM.equals(encMethod)
                && !EncryptionMethod.A128GCM.equals(encMethod)
                && !EncryptionMethod.A192GCM.equals(encMethod)) {
            throw new GeneralSecurityException(
                    "Unsupported JWE content encryption method for HSM: " + encMethod
                            + ". Supported: A128GCM, A192GCM, A256GCM");
        }
    }

    /**
     * Get the hash algorithm name for OAEP unpadding based on the JWE algorithm.
     */
    static String getOAEPHashAlgorithm(JWEAlgorithm algorithm) {

        if (JWEAlgorithm.RSA_OAEP_256.equals(algorithm)) {
            return "SHA-256";
        } else if (JWEAlgorithm.RSA_OAEP_384.equals(algorithm)) {
            return "SHA-384";
        } else if (JWEAlgorithm.RSA_OAEP_512.equals(algorithm)) {
            return "SHA-512";
        }
        // RSA-OAEP uses SHA-1
        return "SHA-1";
    }

    /**
     * Get the SunPKCS11 provider associated with the HSM private key.
     *
     * @param privateKey the private key (expected to be a P11Key from HSM)
     * @return the SunPKCS11 provider, or null if not found
     */
    static Provider getHSMProvider(PrivateKey privateKey) {

        // First, try to get the provider from the key's class if it's a P11Key
        String keyClassName = privateKey.getClass().getName();
        if (keyClassName.contains("P11Key") || keyClassName.contains("pkcs11")) {
            // The key is from PKCS#11, find the corresponding provider
            for (Provider provider : Security.getProviders()) {
                if (provider.getName().startsWith("SunPKCS11")) {
                    // Check if this provider supports the required algorithm
                    if (provider.getService("Cipher", "RSA/ECB/NoPadding") != null) {
                        return provider;
                    }
                }
            }
            // If no provider with RSA Cipher support found, return first SunPKCS11
            for (Provider provider : Security.getProviders()) {
                if (provider.getName().startsWith("SunPKCS11")) {
                    return provider;
                }
            }
        }
        return null;
    }

    /**
     * Manual OAEP unpadding (RFC 3447 Section 7.1.2).
     * Performs the OAEP decode in software after raw RSA decrypt in HSM.
     * No secret material is involved - only mathematical operations on the padding structure.
     *
     * @param em         The raw RSA decrypted bytes (encoded message)
     * @param hashAlgo   The hash algorithm (e.g., "SHA-256" for RSA-OAEP-256)
     * @param keyBitLen  The RSA key bit length
     * @return The unpadded message (CEK bytes), or null if padding is invalid
     */
    static byte[] oaepUnpad(byte[] em, String hashAlgo, int keyBitLen)
            throws GeneralSecurityException {

        MessageDigest md = MessageDigest.getInstance(hashAlgo);
        int hLen = md.getDigestLength();
        int k = keyBitLen / 8;

        // Ensure em is k bytes (pad with leading zeros if needed - raw RSA may strip leading zeros)
        if (em.length < k) {
            byte[] padded = new byte[k];
            System.arraycopy(em, 0, padded, k - em.length, em.length);
            em = padded;
        }

        // em = 0x00 || maskedSeed || maskedDB
        if (em[0] != 0) {
            throw new GeneralSecurityException("OAEP unpadding failed - first byte is not 0x00");
        }

        byte[] maskedSeed = new byte[hLen];
        System.arraycopy(em, 1, maskedSeed, 0, hLen);

        byte[] maskedDB = new byte[k - hLen - 1];
        System.arraycopy(em, 1 + hLen, maskedDB, 0, maskedDB.length);

        // seedMask = MGF1(maskedDB, hLen)
        byte[] seedMask = mgf1(maskedDB, hLen, md);
        byte[] seed = xor(maskedSeed, seedMask);

        // dbMask = MGF1(seed, k - hLen - 1)
        byte[] dbMask = mgf1(seed, k - hLen - 1, md);
        byte[] db = xor(maskedDB, dbMask);

        // db = lHash' || PS (zeros) || 0x01 || M
        // Verify lHash (label hash - empty label)
        byte[] lHash = md.digest(new byte[0]);
        for (int i = 0; i < hLen; i++) {
            if (db[i] != lHash[i]) {
                throw new GeneralSecurityException("OAEP unpadding failed - label hash mismatch");
            }
        }

        // Find 0x01 separator after padding zeros
        int msgStart = -1;
        for (int i = hLen; i < db.length; i++) {
            if (db[i] == 0x01) {
                msgStart = i + 1;
                break;
            } else if (db[i] != 0x00) {
                throw new GeneralSecurityException("OAEP unpadding failed - invalid padding byte");
            }
        }
        if (msgStart < 0) {
            throw new GeneralSecurityException("OAEP unpadding failed - 0x01 separator not found");
        }

        byte[] message = new byte[db.length - msgStart];
        System.arraycopy(db, msgStart, message, 0, message.length);
        return message;
    }

    /**
     * MGF1 Mask Generation Function (RFC 3447 B.2.1).
     */
    static byte[] mgf1(byte[] seed, int maskLen, MessageDigest md) {

        int hLen = md.getDigestLength();
        int iterations = (maskLen + hLen - 1) / hLen;
        byte[] mask = new byte[maskLen];
        int offset = 0;

        for (int counter = 0; counter < iterations; counter++) {
            md.reset();
            md.update(seed);
            md.update(new byte[]{
                    (byte) (counter >>> 24), (byte) (counter >>> 16),
                    (byte) (counter >>> 8), (byte) counter
            });
            byte[] hash = md.digest();
            int toCopy = Math.min(hLen, maskLen - offset);
            System.arraycopy(hash, 0, mask, offset, toCopy);
            offset += toCopy;
        }
        return mask;
    }

    /**
     * XOR two byte arrays of equal length.
     */
    static byte[] xor(byte[] a, byte[] b) {

        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }
}
