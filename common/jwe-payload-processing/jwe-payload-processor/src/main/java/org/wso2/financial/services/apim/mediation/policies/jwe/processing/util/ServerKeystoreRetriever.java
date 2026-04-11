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

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.SynapseException;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.financial.services.apim.mediation.policies.jwe.processing.constants.JwePayloadProcessingConstants;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

/**
 * Utility to retrieve Server certificates.
 * Supports both file-based keystore and HSM (PKCS#11) via Carbon KeyStoreManager.
 */
public class ServerKeystoreRetriever {

    private static final Log log = LogFactory.getLog(ServerKeystoreRetriever.class);

    private KeyStore keyStore = null;
    private static final Object lock = new Object();
    static ServerKeystoreRetriever retriever;

    // Super tenant ID used for KeyStoreManager
    private static final int SUPER_TENANT_ID = -1234;

    // Internal KeyStore Password (only used for file-based keystore).
    private char[] keyStorePassword;

    // Cached HSM private key (loaded once via KeyStoreManager)
    private static volatile Key hsmPrivateKey;

    // Flag indicating whether HSM is enabled
    private final boolean hsmEnabled;

    /**
     * Private Constructor of config parser.
     */
    private ServerKeystoreRetriever() {

        hsmEnabled = checkHSMEnabled();

        if (!hsmEnabled) {
            // File-based keystore path (original behavior)
            String keyStoreLocation = ServerConfiguration.getInstance()
                    .getFirstProperty(JwePayloadProcessingConstants.KEYSTORE_LOCATION_CONF_KEY);
            String keyStorePasswordConfig = ServerConfiguration.getInstance()
                    .getFirstProperty(JwePayloadProcessingConstants.KEYSTORE_PASS_CONF_KEY);
            keyStore = loadKeyStore(keyStoreLocation, keyStorePasswordConfig);
            keyStorePassword = keyStorePasswordConfig.toCharArray();
            log.info("JWE ServerKeystoreRetriever initialized with file-based keystore.");
        } else {
            log.info("JWE ServerKeystoreRetriever initialized with HSM mode (KeyStoreManager).");
        }
    }

    /**
     * Singleton getInstance method to create only one object.
     *
     * @return ServerKeystoreRetriever object
     */
    public static ServerKeystoreRetriever getInstance() {

        synchronized (lock) {
            if (retriever == null) {
                retriever = new ServerKeystoreRetriever();
            }
        }
        return retriever;
    }

    /**
     * Check if HSM is enabled via server configuration.
     *
     * @return true if HSM is enabled
     */
    private static boolean checkHSMEnabled() {

        String hsmEnabledStr = org.wso2.carbon.utils.CarbonUtils.getServerConfiguration()
                .getFirstProperty("Security.HSM.Enabled");
        boolean enabled = Boolean.parseBoolean(hsmEnabledStr);
        if (log.isDebugEnabled()) {
            log.debug("HSM Status Check: " + enabled + " (Raw value: " + hsmEnabledStr + ")");
        }
        return enabled;
    }

    /**
     * Returns whether HSM is enabled.
     *
     * @return true if HSM is enabled
     */
    public boolean isHSMEnabled() {

        return hsmEnabled;
    }

    /**
     * Load the keystore when the location and password is provided.
     *
     * @param keyStoreLocation Location of the keystore
     * @param keyStorePassword Keystore password
     * @return Keystore as an object
     */
    public static KeyStore loadKeyStore(String keyStoreLocation, String keyStorePassword) {

        KeyStore keyStore;

        try (FileInputStream inputStream = new FileInputStream(keyStoreLocation)) {
            keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(inputStream, keyStorePassword.toCharArray());
            return keyStore;
        } catch (KeyStoreException e) {
            throw new SynapseException("Error while retrieving aliases from keystore: " + keyStoreLocation, e);
        } catch (IOException | CertificateException | NoSuchAlgorithmException e) {
            throw new SynapseException("Error while loading keystore", e);
        }
    }

    /**
     * Returns the private key for JWE decryption.
     * When HSM is enabled, uses Carbon KeyStoreManager (HSM-aware).
     * When HSM is not enabled, uses the file-based keystore (original behavior).
     *
     * @param alias Alias of the key to retrieve (used only in file-based mode)
     * @return Key The private key
     */
    public Key getSigningKey(String alias) {

        if (hsmEnabled) {
            return getHSMPrivateKey();
        }

        // Original file-based keystore path
        if (StringUtils.isNotBlank(alias)) {
            try {
                return keyStore.getKey(alias, keyStorePassword);
            } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
                throw new SynapseException("Unable to retrieve certificate", e);
            }
        }

        return null;
    }

    /**
     * Returns the private key from KeyStoreManager (HSM-aware).
     * Uses volatile double-checked locking for thread-safe lazy initialization.
     *
     * @return Key The HSM-backed private key
     */
    private Key getHSMPrivateKey() {

        Key localKey = hsmPrivateKey;
        if (localKey == null) {
            synchronized (ServerKeystoreRetriever.class) {
                localKey = hsmPrivateKey;
                if (localKey == null) {
                    try {
                        KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(SUPER_TENANT_ID);
                        localKey = keyStoreManager.getDefaultPrivateKey();
                        hsmPrivateKey = localKey;
                        log.info("JWE decryption key loaded from KeyStoreManager. Key type: "
                                + localKey.getClass().getName());
                    } catch (Exception e) {
                        throw new SynapseException(
                                "Unable to retrieve private key from KeyStoreManager for JWE decryption", e);
                    }
                }
            }
        }
        return localKey;
    }
}
