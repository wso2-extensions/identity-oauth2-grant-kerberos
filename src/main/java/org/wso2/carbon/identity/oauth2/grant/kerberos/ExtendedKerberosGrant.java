/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oauth2.grant.kerberos;

import org.wso2.carbon.apimgt.keymgt.ScopesIssuer;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

/**
 * Extended version of the Kerberos grant
 * <p>
 * This this used to support the scope validation of the WSO2 API Manager
 */
public class ExtendedKerberosGrant extends KerberosGrant {

    @Override
    public boolean validateScope(OAuthTokenReqMessageContext tokReqMsgCtx) {
        // APIM specific scope handling
        return ScopesIssuer.getInstance().setScopes(tokReqMsgCtx);
    }

}
