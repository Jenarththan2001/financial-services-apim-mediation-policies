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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.core.util.KeyStoreManager;

import java.security.Key;

/**
 * Utility to retrieve Server certificates for JWE decryption.
 * Uses Carbon KeyStoreManager which is HSM-aware and automatically handles
 * both PKCS#11 (HSM) and file-based (JKS) keystores based on server configuration.
 */
public class ServerKeystoreRetriever {

    private static final Log log = LogFactory.getLog(ServerKeystoreRetriever.class);

    private static final Object lock = new Object();
    static ServerKeystoreRetriever retriever;

    // Super tenant ID used for KeyStoreManager
    private static final int SUPER_TENANT_ID = -1234;

    // Cached private key (loaded once via KeyStoreManager)
    private volatile Key privateKey;

    /**
     * Private Constructor.
     */
    private ServerKeystoreRetriever() {
        log.info("JWE ServerKeystoreRetriever initialized (HSM-aware via KeyStoreManager)");
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
     * Returns the private key for JWE decryption.
     * KeyStoreManager is HSM-aware and will return:
     * - PKCS#11 backed key (P11PrivateKey) when HSM is configured
     * - File-based key (RSAPrivateCrtKeyImpl) when HSM is not configured
     *
     * Uses double-checked locking for thread-safe lazy initialization.
     *
     * @param alias Alias of the signing key (not used when KeyStoreManager returns default key)
     * @return Key The private key for JWE decryption, or null if key cannot be loaded
     */
    public Key getSigningKey(String alias) {

        Key localKey = privateKey;
        if (localKey == null) {
            synchronized (this) {
                localKey = privateKey;
                if (localKey == null) {
                    if (log.isDebugEnabled()) {
                        log.debug("Loading JWE decryption key from KeyStoreManager (HSM-aware)");
                    }
                    try {
                        KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(SUPER_TENANT_ID);
                        localKey = keyStoreManager.getDefaultPrivateKey();
                        privateKey = localKey;
                        if (localKey != null) {
                            log.info("JWE decryption key loaded successfully. Key type: "
                                    + localKey.getClass().getName());
                        }
                    } catch (Exception e) {
                        log.error("Unable to retrieve private key from KeyStoreManager for JWE decryption", e);
                        // Return null to maintain backward compatibility instead of throwing exception
                        return null;
                    }
                }
            }
        }
        return localKey;
    }
}
