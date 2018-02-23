/*
 *  Copyright (c) 2005-2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.user.core.config;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMAttribute;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMFactory;
import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.apache.axiom.om.util.Base64;
import org.apache.axiom.om.xpath.AXIOMXPath;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jaxen.JaxenException;
import org.osgi.framework.BundleContext;
import org.wso2.carbon.CarbonException;
import org.wso2.carbon.base.api.ServerConfigurationService;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreConfigConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.internal.UserStoreMgtDSComponent;
import org.wso2.carbon.user.core.tracker.UserStoreManagerRegistry;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.CarbonUtils;
import org.wso2.securevault.SecretResolver;
import org.wso2.securevault.SecretResolverFactory;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;

public class UserStoreConfigXMLProcessor {

    private static final Log log = LogFactory.getLog(UserStoreConfigXMLProcessor.class);
    private static BundleContext bundleContext;
    private static PrivateKey privateKey = getPrivateKey();
    private static Certificate certificate = getCertificate();
    private static final String CIPHER_TRANSFORMATION_SYSTEM_PROPERTY = "org.wso2.CipherTransformation";
    private SecretResolver secretResolver;
    private String filePath = null;
    private Gson gson = new Gson();
    private boolean isMigrationRequired = false;

    private static final char[] HEX_CHARACTERS = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B',
                                                            'C', 'D', 'E', 'F'};

    public UserStoreConfigXMLProcessor(String path) {
        this.filePath = path;
    }

    public static void setBundleContext(BundleContext bundleContext) {
        UserStoreConfigXMLProcessor.bundleContext = bundleContext;
    }

    public static OMElement serialize(RealmConfiguration realmConfig) {
        OMFactory factory = OMAbstractFactory.getOMFactory();

        // add the user store manager properties
        OMElement userStoreManagerElement = factory.createOMElement(new QName(
                UserCoreConstants.RealmConfig.LOCAL_NAME_USER_STORE_MANAGER));
        addPropertyElements(factory, userStoreManagerElement, realmConfig.getUserStoreClass(), realmConfig.getUserStoreProperties());

        return userStoreManagerElement;
    }

    /**
     * Add all the user store property elements
     *
     * @param factory
     * @param parent
     * @param className
     * @param properties
     */
    private static void addPropertyElements(OMFactory factory, OMElement parent, String className,
                                            Map<String, String> properties) {
        if (className != null) {
            parent.addAttribute(UserCoreConstants.RealmConfig.ATTR_NAME_CLASS, className, null);
        }
        Iterator<Map.Entry<String, String>> ite = properties.entrySet().iterator();
        while (ite.hasNext()) {
            Map.Entry<String, String> entry = ite.next();
            String name = entry.getKey();
            String value = entry.getValue();
            OMElement propElem = factory.createOMElement(new QName(
                    UserCoreConstants.RealmConfig.LOCAL_NAME_PROPERTY));
            OMAttribute propAttr = factory.createOMAttribute(
                    UserCoreConstants.RealmConfig.ATTR_NAME_PROP_NAME, null, name);
            propElem.addAttribute(propAttr);
            propElem.setText(value);
            parent.addChild(propElem);
        }
    }

    public RealmConfiguration buildUserStoreConfigurationFromFile() throws UserStoreException {
        OMElement realmElement;
        try {
            realmElement = getRealmElement();
            return buildUserStoreConfiguration(realmElement);
        } catch (Exception e) {
            String message = "Error while building user store manager from file";
            if (log.isDebugEnabled()) {
                log.debug(message, e);
            }
            throw new UserStoreException(message, e);
        }

    }

    public RealmConfiguration buildUserStoreConfiguration(OMElement userStoreElement) throws org.wso2.carbon.user.api.UserStoreException {
        RealmConfiguration realmConfig = null;
        String userStoreClass = null;
        Map<String, String> userStoreProperties = null;
        boolean passwordsExternallyManaged = false;
        XMLProcessorUtils xmlProcessorUtils = new XMLProcessorUtils();

        realmConfig = new RealmConfiguration();
//        String[] fileNames = filePath.split(File.separator);
        String pattern = Pattern.quote(System.getProperty("file.separator"));
        String[] fileNames = filePath.split(pattern);
        String fileName = fileNames[fileNames.length - 1].replace(".xml", "").replace("_", ".");
        RealmConfiguration primaryRealm = UserStoreMgtDSComponent.getRealmService().getBootstrapRealmConfiguration();
        userStoreClass = userStoreElement.getAttributeValue(new QName(UserCoreConstants.RealmConfig.ATTR_NAME_CLASS));
        userStoreProperties = getChildPropertyElements(userStoreElement, secretResolver);

        // Check whether if it is required to migrate encrypted data
        if (isMigrationRequired) {
            // Return null since required to migrate to self-contained ciphertext
            return null;
        }
        if (!userStoreProperties.get(UserStoreConfigConstants.DOMAIN_NAME).equalsIgnoreCase(fileName)) {
            throw new UserStoreException("File name is required to be the user store domain name(eg.: wso2.com-->wso2_com.xml).");
        }

//        if(!xmlProcessorUtils.isValidDomain(fileName,true)){
//            throw new UserStoreException("Invalid domain name provided");
//        }

        if (!xmlProcessorUtils.isMandatoryFieldsProvided(userStoreProperties, UserStoreManagerRegistry.getUserStoreProperties(userStoreClass).getMandatoryProperties())) {
            throw new UserStoreException("A required mandatory field is missing.");
        }

        String sIsPasswordExternallyManaged = userStoreProperties
                .get(UserCoreConstants.RealmConfig.LOCAL_PASSWORDS_EXTERNALLY_MANAGED);

        if (null != sIsPasswordExternallyManaged
                && !sIsPasswordExternallyManaged.trim().equals("")) {
            passwordsExternallyManaged = Boolean.parseBoolean(sIsPasswordExternallyManaged);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("External password management is disabled.");
            }
        }

        Map<String, String> multipleCredentialsProperties = getMultipleCredentialsProperties(userStoreElement);

        realmConfig.setUserStoreClass(userStoreClass);
        realmConfig.setAuthorizationManagerClass(primaryRealm.getAuthorizationManagerClass());
        realmConfig.setEveryOneRoleName(UserCoreUtil.addDomainToName(primaryRealm.getEveryOneRoleName(),
                UserCoreConstants.INTERNAL_DOMAIN));
        realmConfig.setUserStoreProperties(userStoreProperties);
        realmConfig.setPasswordsExternallyManaged(passwordsExternallyManaged);
        realmConfig.setAuthzProperties(primaryRealm.getAuthzProperties());
        realmConfig.setRealmProperties(primaryRealm.getRealmProperties());
        realmConfig.setPasswordsExternallyManaged(primaryRealm.isPasswordsExternallyManaged());
        realmConfig.addMultipleCredentialProperties(userStoreClass, multipleCredentialsProperties);

        if (realmConfig
                .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_MAX_USER_LIST) == null) {
            realmConfig.getUserStoreProperties().put(
                    UserCoreConstants.RealmConfig.PROPERTY_MAX_USER_LIST,
                    UserCoreConstants.RealmConfig.PROPERTY_VALUE_DEFAULT_MAX_COUNT);
        }

        if (realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_READ_ONLY) == null) {
            realmConfig.getUserStoreProperties().put(
                    UserCoreConstants.RealmConfig.PROPERTY_READ_ONLY,
                    UserCoreConstants.RealmConfig.PROPERTY_VALUE_DEFAULT_READ_ONLY);
        }

        return realmConfig;
    }

    private Map<String, String> getChildPropertyElements(OMElement omElement, SecretResolver secretResolver)
            throws org.wso2.carbon.user.api.UserStoreException {
        String domainName = "";
        try {
            AXIOMXPath xPath = new AXIOMXPath(UserCoreConstants.RealmConfig.DOMAIN_NAME_XPATH);
            OMElement val = (OMElement) xPath.selectSingleNode(omElement);
            if (val != null) {
                domainName = "." + val.getText();
            }
        } catch (Exception e) {
            log.debug("Error While getting DomainName from Configurations ");
        }

        Map<String, String> map = new HashMap<String, String>();
        Iterator<?> ite = omElement.getChildrenWithName(new QName(
                UserCoreConstants.RealmConfig.LOCAL_NAME_PROPERTY));
        boolean tokenProtected = false;
        while (ite.hasNext()) {
            OMElement propElem = (OMElement) ite.next();
            String propName = propElem.getAttributeValue(new QName(
                    UserCoreConstants.RealmConfig.ATTR_NAME_PROP_NAME));
            String propValue = propElem.getText();
            if (secretResolver != null && secretResolver.isInitialized()) {
                if (secretResolver.isTokenProtected("UserManager.Configuration.Property."
                        + propName + domainName)) {
                    propValue = secretResolver.resolve("UserManager.Configuration.Property."
                            + propName + domainName);
                }
                if (secretResolver.isTokenProtected("UserStoreManager.Property." + propName + domainName)) {
                    propValue = secretResolver.resolve("UserStoreManager.Property." + propName + domainName);
                    tokenProtected = true;
                }
            }
            if (!tokenProtected && propValue != null) {
                propValue = resolveEncryption(propElem);
            }
            tokenProtected = false;
            if (propName != null && propValue != null) {
                map.put(propName.trim(), propValue.trim());
            }

        }
        return map;
    }

    private Map<String, String> getMultipleCredentialsProperties(OMElement omElement) {
        Map<String, String> map = new HashMap<String, String>();
        OMElement multipleCredentialsEl = omElement.getFirstChildWithName(new QName(
                UserCoreConstants.RealmConfig.LOCAL_NAME_MULTIPLE_CREDENTIALS));
        if (multipleCredentialsEl != null) {
            Iterator<?> ite = multipleCredentialsEl
                    .getChildrenWithLocalName(UserCoreConstants.RealmConfig.LOCAL_NAME_CREDENTIAL);
            while (ite.hasNext()) {

                Object OMObj = ite.next();
                if (!(OMObj instanceof OMElement)) {
                    continue;
                }
                OMElement credsElem = (OMElement) OMObj;
                String credsType = credsElem.getAttributeValue(new QName(
                        UserCoreConstants.RealmConfig.ATTR_NAME_TYPE));
                String credsClassName = credsElem.getText();
                map.put(credsType.trim(), credsClassName.trim());
            }
        }
        return map;
    }

    /**
     * Read in realm element from config file
     *
     * @return
     * @throws javax.xml.stream.XMLStreamException
     * @throws java.io.IOException
     * @throws org.wso2.carbon.user.core.UserStoreException
     */
    private OMElement getRealmElement() throws XMLStreamException, IOException, UserStoreException {
        StAXOMBuilder builder = null;
        InputStream inStream = null;
        inStream = new FileInputStream(filePath);

        try {
            inStream = CarbonUtils.replaceSystemVariablesInXml(inStream);
            builder = new StAXOMBuilder(inStream);
            OMElement documentElement = builder.getDocumentElement();
            setSecretResolver(documentElement);

            return documentElement;
        } catch (CarbonException e) {
            if (log.isDebugEnabled()) {
                log.debug(e.getMessage(), e);
            }
            throw new UserStoreException(e.getMessage(), e);
        } finally {
            inStream.close();
        }
    }

    public void setSecretResolver(OMElement rootElement) {
        secretResolver = SecretResolverFactory.create(rootElement, true);
    }

    /**
     * decrypts encrypted text value if the property element has the attribute encrypt="true"
     *
     * @param propElem Property OMElement
     * @return decrypted text value
     */
    private String resolveEncryption(OMElement propElem) throws org.wso2.carbon.user.api.UserStoreException {
        String propValue = propElem.getText();
        if (propValue != null) {
            String secretPropName = propElem.getAttributeValue(new QName("encrypted"));
            if (secretPropName != null && secretPropName.equalsIgnoreCase("true")) {
                if (log.isDebugEnabled()) {
                    log.debug("Eligible to be decrypted=" + propElem.getAttributeValue(new QName(
                            UserCoreConstants.RealmConfig.ATTR_NAME_PROP_NAME)));
                }
                try {
                    propValue = decryptProperty(propValue);
                } catch (GeneralSecurityException e) {
                    String errMsg = "encryption of Property=" + propElem.getAttributeValue(
                            new QName(UserCoreConstants.RealmConfig.ATTR_NAME_PROP_NAME))
                            + " failed";
                    log.error(errMsg, e);
                }
            }
        }
        return propValue;
    }

    /**
     * Initializes and assign the keyStoreCipher only for the first time.
     */
    private static PrivateKey getPrivateKey() {
        ServerConfigurationService serverConfigurationService =
                UserStoreMgtDSComponent.getServerConfigurationService();

        if (serverConfigurationService == null) {
            String message = "Key store initialization for decrypting secondary store failed due to" +
                    " serverConfigurationService is null while attempting to decrypt secondary store";
            log.error(message);
            return null;
        }

        String password = serverConfigurationService.getFirstProperty(
                "Security.KeyStore.Password");
        String keyPass = serverConfigurationService.getFirstProperty(
                "Security.KeyStore.KeyPassword");
        String keyAlias = serverConfigurationService.getFirstProperty(
                "Security.KeyStore.KeyAlias");
        InputStream in = null;
        try {
            KeyStore store = KeyStore.getInstance(
                    serverConfigurationService.getFirstProperty(
                            "Security.KeyStore.Type"));
            String file = new File(serverConfigurationService.getFirstProperty(
                    "Security.KeyStore.Location")).getAbsolutePath();
            in = new FileInputStream(file);
            store.load(in, password.toCharArray());
            return (PrivateKey) store.getKey(keyAlias, keyPass.toCharArray());
        } catch (FileNotFoundException e) {
            String errorMsg = "Keystore File Not Found in configured location";
            log.error(errorMsg, e);
        } catch (IOException e) {
            String errorMsg = "Keystore File IO operation failed";
            log.error(errorMsg, e);
        } catch (KeyStoreException e) {
            String errorMsg = "Faulty keystore";
            log.error(errorMsg, e);
        } catch (GeneralSecurityException e) {
            String errorMsg = "Some parameters assigned to access the " +
                    "keystore is invalid";
            log.error(errorMsg, e);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                    log.error("Error occurred while closing Registry key store file", e);
                }
            }
        }
        return null;
    }

    /**
     * Function to retrieve certificate
     */
    private static Certificate getCertificate() {
        ServerConfigurationService serverConfigurationService =
                UserStoreMgtDSComponent.getServerConfigurationService();

        if (serverConfigurationService == null) {
            String message = "Key store initialization for decrypting secondary store failed due to" +
                    " serverConfigurationService is null while attempting to decrypt secondary store";
            log.error(message);
            return null;
        }

        String password = serverConfigurationService.getFirstProperty(
                "Security.KeyStore.Password");
        String keyAlias = serverConfigurationService.getFirstProperty(
                "Security.KeyStore.KeyAlias");
        InputStream in = null;
        try {
            KeyStore store = KeyStore.getInstance(
                    serverConfigurationService.getFirstProperty(
                            "Security.KeyStore.Type"));
            String file = new File(serverConfigurationService.getFirstProperty(
                    "Security.KeyStore.Location")).getAbsolutePath();
            in = new FileInputStream(file);
            store.load(in, password.toCharArray());

            return  store.getCertificateChain(keyAlias)[0];
        } catch (FileNotFoundException e) {
            String errorMsg = "Keystore File Not Found in configured location";
            log.error(errorMsg, e);
        } catch (IOException e) {
            String errorMsg = "Keystore File IO operation failed";
            log.error(errorMsg, e);
        } catch (KeyStoreException e) {
            String errorMsg = "Faulty keystore";
            log.error(errorMsg, e);
        } catch (GeneralSecurityException e) {
            String errorMsg = "Some parameters assigned to access the " +
                    "keystore is invalid";
            log.error(errorMsg, e);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                    log.error("Error occurred while closing Registry key store file", e);
                }
            }
        }
        return null;
    }

    private String decryptProperty(String propValue)
            throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException,
            org.wso2.carbon.user.api.UserStoreException, InvalidKeyException, BadPaddingException,
            IllegalBlockSizeException {

        Cipher keyStoreCipher;
        String cipherTransformation = System.getProperty(CIPHER_TRANSFORMATION_SYSTEM_PROPERTY);
        byte[] cipherTextBytes = Base64.decode(propValue.trim());

        privateKey = (privateKey == null) ? getPrivateKey() : privateKey;
        if (privateKey == null) {
            throw new org.wso2.carbon.user.api.UserStoreException(
                    "Private key initialization failed. Cannot decrypt the userstore password.");
        }

        if(cipherTransformation != null) {
            //extract the original cipher if custom transformation is used configured in carbon.properties.
            CipherHolder cipherHolder = cipherTextToCipherHolder(cipherTextBytes);
            if (cipherHolder != null) {
                //cipher with meta data.
                if (log.isDebugEnabled()) {
                    log.debug("Cipher transformation for decryption : " + cipherHolder.getTransformation());
                }
                keyStoreCipher = Cipher.getInstance(cipherHolder.getTransformation(), "BC");
                cipherTextBytes = cipherHolder.getCipherBase64Decoded();
            } else {
                isMigrationRequired = true;
                //If custom cipher transformation configured, but still there is old cipher in the system or
                // encrypted cipher using custom transformation configured in carbon.properties.
                // Unfortunately we have to check whether the encryption is done in RSA or custom transformation
                // configured via carbon.properties without meta data.
                byte[] decyptedValue;
                try {
                    if (cipherTextBytes.length == 0) {
                        decyptedValue = "".getBytes();
                        if (log.isDebugEnabled()) {
                            log.debug("Empty value for plainTextBytes null will persist to DB");
                        }
                    } else {
                        keyStoreCipher = Cipher.getInstance(cipherTransformation, "BC");
                        keyStoreCipher.init(Cipher.DECRYPT_MODE, privateKey);
                        decyptedValue = keyStoreCipher.doFinal(cipherTextBytes);
                        if (log.isDebugEnabled()) {
                            log.debug("Given cipher text encrypted encrypted transformation: "
                                    + cipherTransformation);
                        }
                    }
                    //if decryption success encryption is transformation configured in carbon.properties.
                    return new String(decyptedValue);
                } catch (BadPaddingException e) {
                    //This means given cipher text is encrypted by RSA as final option.
                    if (log.isDebugEnabled()) {
                        log.debug("Given cipher text is encrypted by RSA");
                    }
                    keyStoreCipher = Cipher.getInstance("RSA", "BC");
                }
            }
        } else {
            keyStoreCipher = Cipher.getInstance("RSA", "BC");
        }
        keyStoreCipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(keyStoreCipher.doFinal(cipherTextBytes));
    }

    private byte[] encrypt(byte[] plainTextBytes) throws UserStoreException {

        byte[] encryptedKey;
        certificate = (certificate == null) ? getCertificate() : certificate;
        if (certificate == null) {
            throw new UserStoreException("Certificate initialization failed. Cannot encrypt the userstore "
                    + "sensitive content.");
        }
        String cipherTransformation = System.getProperty(CIPHER_TRANSFORMATION_SYSTEM_PROPERTY);
        try {
            if (log.isDebugEnabled()) {
                log.debug("Cipher transformation for encryption : " + cipherTransformation);
            }
            Cipher keyStoreCipher = Cipher.getInstance(cipherTransformation, "BC");
            keyStoreCipher.init(Cipher.ENCRYPT_MODE, certificate.getPublicKey());
            encryptedKey = keyStoreCipher.doFinal(plainTextBytes);
            encryptedKey = createSelfContainedCiphertext(encryptedKey, cipherTransformation, certificate);
        } catch (GeneralSecurityException e) {
            // Error occurred while encrypting.
            throw new UserStoreException("Error occurred while encrypting", e);
        }

        return encryptedKey;
    }

    /**
     * This function is added for ondemand data migration for OAEP fix
     *
     * @throws UserStoreException
     * @throws IOException
     * @throws CarbonException
     */
    public RealmConfiguration performUserStoreEncryptionDataMigration() throws UserStoreException, IOException, CarbonException {

        log.info("Start migrating encrypted data of : " + filePath);

        InputStream inStream = null;
        StAXOMBuilder builder = null;
        OMElement documentElement = null;
        byte[] buffer = null;

        // Buffer user store config file content.
        try {
            if (log.isDebugEnabled()) {
                log.debug("Read userstore configuration file : " + filePath);
            }
            inStream = new FileInputStream(filePath);
            buffer = IOUtils.toByteArray(inStream);
        } catch (FileNotFoundException e) {
            // Error occurred while reading user store config file
            throw new UserStoreException("Error occurred while reading user store config file : " + filePath, e);
        } finally {
            if (inStream != null) {
                inStream.close();
            }
        }

        OutputStream outputStream = null;
        try {
            ByteArrayInputStream inputStreamBuffer = new ByteArrayInputStream(buffer);
            builder = new StAXOMBuilder(inputStreamBuffer);
            documentElement = builder.getDocumentElement();

            AXIOMXPath xPath = new AXIOMXPath(UserCoreConstants.RealmConfig.ENCRYPTED_PROPERTIES_XPATH);
            List encryptedNodes = xPath.selectNodes(documentElement);

            // Decrypt and encrypt as self-contained ciphertext
            for (Object node : encryptedNodes) {
                OMElement propElement = (OMElement) node;
                String decryptedValue = decryptProperty(propElement.getText());
                propElement.setText(Base64.encode(encrypt(decryptedValue.getBytes())));
            }
            if (log.isDebugEnabled()) {
                log.debug("Write back migrated content back to userstore configuration file : " + filePath);
            }
            outputStream = new FileOutputStream(filePath);
            documentElement.serialize(outputStream);
        } catch (JaxenException e) {
            // Error occurred while XPath evaluation
            throw new UserStoreException("Error occurred while XPath evaluation", e);
        } catch (GeneralSecurityException | org.wso2.carbon.user.api.UserStoreException e) {
            // Error occurred while decrypting
            throw new UserStoreException("Error occurred while decrypting", e);
        } catch (XMLStreamException e) {
            // Error occurred while building document element of userstore configuration
            throw new UserStoreException("Error occurred while building document element of userstore configuration", e);
        } finally {
            if (outputStream != null) {
                outputStream.close();
            }
        }
        // Update completion of migration
        isMigrationRequired = false;
        log.info("Successfully migrated encrypted data of : " + filePath);

        // Rebuild user store configuration from the file.
        return buildUserStoreConfigurationFromFile();
    }

    /**
     * Function to convert cipher byte array to {@link CipherHolder}.
     *
     * @param cipherText cipher text as a byte array
     * @return if cipher text is not a cipher with meta data
     */
    private CipherHolder cipherTextToCipherHolder(byte[] cipherText) {

        String cipherStr = new String(cipherText, Charset.defaultCharset());
        try {
            return gson.fromJson(cipherStr, CipherHolder.class);
        } catch (JsonSyntaxException e) {
            if (log.isDebugEnabled()) {
                log.debug("Deserialization failed since cipher string is not representing cipher with metadata");
            }
            return null;
        }
    }


    /**
     * This function will create self-contained ciphertext with metadata
     *
     * @param originalCipher ciphertext need to wrap with metadata
     * @param transformation transformation used to encrypt ciphertext
     * @param certificate certificate that holds relevant keys used to encrypt
     * @return setf-contained ciphertext
     * @throws CertificateEncodingException
     * @throws NoSuchAlgorithmException
     */
    public byte[] createSelfContainedCiphertext(byte[] originalCipher, String transformation, Certificate certificate)
            throws CertificateEncodingException, NoSuchAlgorithmException {

        CipherHolder cipherHolder = new CipherHolder();
        cipherHolder.setCipherText(Base64.encode(originalCipher));
        cipherHolder.setTransformation(transformation);
        cipherHolder.setThumbPrint(calculateThumbprint(certificate, "SHA-1"), "SHA-1");
        String cipherWithMetadataStr = gson.toJson(cipherHolder);

        if (log.isDebugEnabled()) {
            log.debug("Cipher with meta data : " + cipherWithMetadataStr);
        }
        return cipherWithMetadataStr.getBytes(Charset.defaultCharset());
    }

    private String calculateThumbprint(Certificate certificate, String digest)
            throws NoSuchAlgorithmException, CertificateEncodingException {

        MessageDigest messageDigest = MessageDigest.getInstance(digest);
        messageDigest.update(certificate.getEncoded());
        byte[] digestByteArray = messageDigest.digest();

        //convert digest in form of byte array to hex format
        StringBuffer strBuffer = new StringBuffer();

        for (int i = 0; i < digestByteArray.length; i++) {
            int leftNibble = (digestByteArray[i] & 0xF0) >> 4;
            int rightNibble = (digestByteArray[i] & 0x0F);
            strBuffer.append(HEX_CHARACTERS[leftNibble]).append(HEX_CHARACTERS[rightNibble]);
        }

        return strBuffer.toString();
    }


    /**
     * Holds encrypted cipher with related metadata.
     *
     * IMPORTANT: this is copy of org.wso2.carbon.core.util.CipherHolder, what ever changes applied here need to update
     *              on above
     */
    private class CipherHolder {

        //Base64 encoded ciphertext.
        private String c;

        //Transformation used for encryption, default is "RSA".
        private String t = "RSA";

        //Thumbprint of the certificate.
        private String tp;

        //Digest used to generate certificate thumbprint.
        private String tpd;


        public String getTransformation() {
            return t;
        }

        public void setTransformation(String transformation) {
            this.t = transformation;
        }

        public String getCipherText() {
            return c;
        }

        public byte[] getCipherBase64Decoded() {
            return Base64.decode(c);
        }

        public void setCipherText(String cipher) {
            this.c = cipher;
        }

        public void setCipherBase64Encoded(byte[] cipher) {
            this.c = Base64.encode(cipher);
        }

        public String getThumbPrint() {
            return tp;
        }

        public void setThumbPrint(String tp) {
            this.tp = tp;
        }

        public void setThumbPrint(String tp, String digest) {
            this.tp = tp;
            this.tpd = digest;
        }

        public String getThumbprintDigest() {
            return tpd;
        }

        public void setThumbprintDigest(String digest) {
            this.tpd = digest;
        }
    }
}
