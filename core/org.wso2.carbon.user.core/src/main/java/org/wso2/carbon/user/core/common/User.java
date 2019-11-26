/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.user.core.common;

import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.utils.xml.StringUtils;

import java.io.Serializable;
import java.util.Map;

/**
 * User class.
 */
public class User implements Serializable {

    private static final long serialVersionUID = -8811345359211553015L;
    private String userID;
    private String username;
    private String preferredUsername;
    private String tenantDomain;
    private String userStoreDomain;
    private Map<String, String> attributes;

    public User() {
        super();
    }

    public User(String userID) {

        this.userID = userID;
    }

    public User(String userID, String username, String preferredUsername) {

        this.userID = userID;
        this.username = username;
        this.preferredUsername = preferredUsername;
    }

    public User(String userID, String username, String preferredUsername, String tenantDomain, String userStoreDomain,
            Map<String, String> attributes) {

        this.userID = userID;
        this.username = username;
        this.preferredUsername = preferredUsername;
        this.tenantDomain = tenantDomain;
        this.userStoreDomain = userStoreDomain;
        this.attributes = attributes;
    }

    public String getUserID() {
        return userID;
    }

    public void setUserID(String userID) {
        this.userID = userID;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getFullQualifiedUsername() {

        String domainSeparator = UserCoreConstants.DOMAIN_SEPARATOR;
        if (!StringUtils.isEmpty(userStoreDomain)) {
            return userStoreDomain + domainSeparator + username;
        }
        return username;
    }

    public String getPreferredUsername() {
        return preferredUsername;
    }

    public void setPreferredUsername(String preferredUsername) {
        this.preferredUsername = preferredUsername;
    }

    public String getTenantDomain() {
        return tenantDomain;
    }

    public void setTenantDomain(String tenantDomain) {
        this.tenantDomain = tenantDomain;
    }

    public String getUserStoreDomain() {
        return userStoreDomain;
    }

    public void setUserStoreDomain(String userStoreDomain) {
        this.userStoreDomain = userStoreDomain;
    }

    public Map<String, String> getAttributes() {
        return attributes;
    }

    public void setAttributes(Map<String, String> attributes) {
        this.attributes = attributes;
    }

}
