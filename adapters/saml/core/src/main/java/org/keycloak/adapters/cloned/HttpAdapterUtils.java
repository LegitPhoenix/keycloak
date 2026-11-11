/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.adapters.cloned;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;

import java.io.IOException;
import java.io.InputStream;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.util.EntityUtils;
import org.keycloak.adapters.saml.descriptor.parsers.SamlDescriptorIDPKeysExtractor;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.saml.common.exceptions.ParsingException;

/**
 * @author <a href="mailto:hmlnarik@redhat.com">Hynek Mlnařík</a>
 */
public class HttpAdapterUtils {

    public static MultivaluedHashMap<String, KeyInfo> downloadKeysFromSamlDescriptor(HttpClient client, String descriptorUrl) throws HttpClientAdapterException {
        validateSamlDescriptorUrl(descriptorUrl);
        try {
            HttpGet httpRequest = new HttpGet(descriptorUrl);
            HttpResponse response = client.execute(httpRequest);
            int status = response.getStatusLine().getStatusCode();
            if (status != HttpStatus.SC_OK) {
                EntityUtils.consumeQuietly(response.getEntity());
                throw new HttpClientAdapterException("Unexpected status = " + status);
            }

            HttpEntity entity = response.getEntity();
            if (entity == null) {
                throw new HttpClientAdapterException("There was no entity.");
            }

            MultivaluedHashMap<String, KeyInfo> res;
            try (InputStream is = entity.getContent()) {
                res = extractKeysFromSamlDescriptor(is);
            }

            EntityUtils.consumeQuietly(entity);

            return res;
        } catch (IOException | ParsingException e) {
            throw new HttpClientAdapterException("IO error", e);
        }
    }

    private static void validateSamlDescriptorUrl(String descriptorUrl) throws HttpClientAdapterException {
        try {
            java.net.URI uri = new java.net.URI(descriptorUrl);
            String scheme = uri.getScheme();
            if (scheme == null || (!scheme.equalsIgnoreCase("https") && !scheme.equalsIgnoreCase("http"))) {
                throw new HttpClientAdapterException("Invalid URL scheme. Only http and https are allowed.");
            }

            String host = uri.getHost();
            if (host == null || host.isEmpty()) {
                throw new HttpClientAdapterException("URL must contain a valid host.");
            }

            String hostLower = host.toLowerCase();
            if (hostLower.equals("localhost") || hostLower.equals("::1") || hostLower.startsWith("127.")) {
                throw new HttpClientAdapterException("Access to localhost is not allowed.");
            }

            java.net.InetAddress addr = java.net.InetAddress.getByName(host);
            if (addr.isLoopbackAddress() || addr.isLinkLocalAddress() || addr.isSiteLocalAddress()) {
                throw new HttpClientAdapterException("Access to private or internal IP addresses is not allowed.");
            }

            byte[] ipBytes = addr.getAddress();
            if (ipBytes.length == 4) {
                int firstOctet = ipBytes[0] & 0xFF;
                int secondOctet = ipBytes[1] & 0xFF;
                if (firstOctet == 10 || 
                    (firstOctet == 172 && secondOctet >= 16 && secondOctet <= 31) ||
                    (firstOctet == 192 && secondOctet == 168) ||
                    (firstOctet == 169 && secondOctet == 254)) {
                    throw new HttpClientAdapterException("Access to private or internal IP addresses is not allowed.");
                }
            }
        } catch (java.net.URISyntaxException e) {
            throw new HttpClientAdapterException("Invalid URL format: " + e.getMessage(), e);
        } catch (java.net.UnknownHostException e) {
            throw new HttpClientAdapterException("Unable to resolve host: " + e.getMessage(), e);
        }
    }

    /**
     * Parses SAML descriptor and extracts keys from it.
     * @param xmlStream
     * @return List of KeyInfo objects containing keys from the descriptor.
     * @throws IOException
     */
    public static MultivaluedHashMap<String, KeyInfo> extractKeysFromSamlDescriptor(InputStream xmlStream) throws ParsingException {
        Object res = new SamlDescriptorIDPKeysExtractor().parse(xmlStream);
        return (MultivaluedHashMap<String, KeyInfo>) res;
    }

}
