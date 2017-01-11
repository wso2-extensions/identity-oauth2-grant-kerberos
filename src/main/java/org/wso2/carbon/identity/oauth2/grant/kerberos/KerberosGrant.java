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

import org.apache.axiom.om.util.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.ResponseHeader;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AbstractAuthorizationGrantHandler;
import sun.security.jgss.GSSUtil;

import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Set;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

/**
 * New grant type for Identity Server
 */
public class KerberosGrant extends AbstractAuthorizationGrantHandler  {

    private static Log log = LogFactory.getLog(KerberosGrant.class);

    private static GSSManager gssManager = GSSManager.getInstance();


    public static final String MOBILE_GRANT_PARAM = "mobileNumber";
    public static final String KERBEROS_GRANT_PARAM = "kerberosToken";
    // Hardcoded for initial testing
    public static final String KERBEROS_SPN = "HTTP/idp.example.com@EXAMPLE.COM";
    public static final String KERBEROS_PASSWORD = "Xyz12345";

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext oAuthTokenReqMessageContext)  throws IdentityOAuth2Exception {

        log.info("kerberos Grant handler is hit");

        boolean authStatus = false;

        // extract request parameters
        RequestParameter[] parameters = oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO().getRequestParameters();

        String mobileNumber = null;
        String kerberosServiceToken = null;

        // find out mobile number
        for(RequestParameter parameter : parameters){
            if(MOBILE_GRANT_PARAM.equals(parameter.getKey())){
                if(parameter.getValue() != null && parameter.getValue().length > 0){
                    mobileNumber = parameter.getValue()[0];
                }
            }
            if(KERBEROS_GRANT_PARAM.equals(parameter.getKey())){
                if(parameter.getValue() != null && parameter.getValue().length > 0){
                    kerberosServiceToken = parameter.getValue()[0];
                }
            }
        }

        GSSCredential gssCredential = null;
        try {
            gssCredential = createCredentials(KERBEROS_SPN, KERBEROS_PASSWORD.toCharArray());
        } catch (LoginException e) {
            e.printStackTrace();
        } catch (PrivilegedActionException e) {
            e.printStackTrace();
        }
        System.out.println("Credentials created successfully");
        System.out.println("Kerberos ticket: " + kerberosServiceToken);

        if (gssCredential != null) {
            try {
                if (validateKerberosTicket(gssCredential, Base64.decode(kerberosServiceToken))) {
                    System.out.println("Kerberos ticket validates");
                }
            } catch (GSSException e) {
                e.printStackTrace();
            }
        }

        if(mobileNumber != null) {
            //validate mobile number
            authStatus =  isValidMobileNumber(mobileNumber);

            if(authStatus) {
                // if valid set authorized mobile number as grant user
                AuthenticatedUser mobileUser = new AuthenticatedUser();
                mobileUser.setUserName(mobileNumber);
                oAuthTokenReqMessageContext.setAuthorizedUser(mobileUser);
                oAuthTokenReqMessageContext.setScope(oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO().getScope());
            } else{
                ResponseHeader responseHeader = new ResponseHeader();
                responseHeader.setKey("SampleHeader-999");
                responseHeader.setValue("Provided Mobile Number is Invalid.");
                oAuthTokenReqMessageContext.addProperty("RESPONSE_HEADERS", new ResponseHeader[]{responseHeader});
            }

        }

	System.out.println("Mobile status: " + authStatus);
        return authStatus;
    }

    private GSSCredential createCredentials (String spnUsername, char[] spnPassword)
            throws LoginException, PrivilegedActionException {
        CallbackHandler callbackHandler = getUserNamePasswordCallbackHandler(spnUsername, spnPassword);

        LoginContext loginContext = new LoginContext(KerberosGrantConstants.SERVER, callbackHandler);
        loginContext.login();

        if (log.isDebugEnabled()) {
            log.debug("Pre-authentication successful for with Kerberos Server.");
        }

        final PrivilegedExceptionAction<GSSCredential> action = new PrivilegedExceptionAction<GSSCredential>() {
            public GSSCredential run() throws GSSException {
                return gssManager.createCredential(null, GSSCredential.INDEFINITE_LIFETIME,
                        GSSUtil.GSS_SPNEGO_MECH_OID, GSSCredential.ACCEPT_ONLY);
            }
        };

        if (log.isDebugEnabled()) {
            Set<Principal> principals = loginContext.getSubject().getPrincipals();
            String principalName = null;
            if (principals != null) {
                principalName = principals.toString();
            }
            log.debug("Creating gss credentials as principal : " + principalName);
        }
        return Subject.doAs(loginContext.getSubject(), action);
    }

    private CallbackHandler getUserNamePasswordCallbackHandler(final String username, final char[] password) {

        return new CallbackHandler() {
            public void handle(final Callback[] callback) {
                for (Callback currentCallBack : callback) {
                    if (currentCallBack instanceof NameCallback) {
                        final NameCallback nameCallback = (NameCallback) currentCallBack;
                        nameCallback.setName(username);
                    } else if (currentCallBack instanceof PasswordCallback) {
                        final PasswordCallback passCallback = (PasswordCallback) currentCallBack;
                        passCallback.setPassword(password);
                    } else {
                        log.error("Unsupported Callback class = " + currentCallBack.getClass().getName());
                    }
                }
            }
        };
    }

    private boolean validateKerberosTicket(GSSCredential gssCredentials, byte[] gssToken) throws GSSException {
        //String fullyQualifiedName = getAuthenticatedUserFromToken(gssCredential, Base64.decode(gssToken));
        GSSContext context = gssManager.createContext(gssCredentials);
        // decrypt the kerberos ticket (GSS token)
        context.acceptSecContext(gssToken, 0, gssToken.length);

        // if we cannot decrypt the GSS Token we return the username as null
        if (!context.isEstablished()) {
            log.error("Unable to decrypt the kerberos ticket as context was not established.");
            return false;
        }

        String loggedInUserName = context.getSrcName().toString();
        String target = context.getTargName().toString();

        System.out.println("Username: " + loggedInUserName);
        System.out.println("Target name: " + target);

        if (log.isDebugEnabled()) {
            String msg = "Extracted details from GSS Token, LoggedIn User : " + loggedInUserName
                    + " , Intended target : " + target;
            log.debug(msg);
        }

        return true;
    }
    public boolean authorizeAccessDelegation(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {

        // if we need to just ignore the end user's extended verification

        return true;

        // if we need to verify with the end user's access delegation by calling callback chain.
        // However, you need to register a callback for this. Default call back just return true.


//        OAuthCallback authzCallback = new OAuthCallback(
//                tokReqMsgCtx.getAuthorizedUser(),
//                tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId(),
//                OAuthCallback.OAuthCallbackType.ACCESS_DELEGATION_TOKEN);
//        authzCallback.setRequestedScope(tokReqMsgCtx.getScope());
//        authzCallback.setCarbonGrantType(org.wso2.carbon.identity.oauth.common.GrantType.valueOf(tokReqMsgCtx.
//                                                            getOauth2AccessTokenReqDTO().getGrantType()));
//        callbackManager.handleCallback(authzCallback);
//        tokReqMsgCtx.setValidityPeriod(authzCallback.getValidityPeriod());
//        return authzCallback.isAuthorized();

    }


    public boolean validateScope(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {


        // if we need to just ignore the scope verification

        return true;

        // if we need to verify with the scope n by calling callback chain.
        // However, you need to register a callback for this. Default call back just return true.
        // you can find more details on writing custom scope validator from here
        // http://xacmlinfo.org/2014/10/24/authorization-for-apis-with-xacml-and-oauth-2-0/

//        OAuthCallback scopeValidationCallback = new OAuthCallback(
//                tokReqMsgCtx.getAuthorizedUser().toString(),
//                tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId(),
//                OAuthCallback.OAuthCallbackType.SCOPE_VALIDATION_TOKEN);
//        scopeValidationCallback.setRequestedScope(tokReqMsgCtx.getScope());
//        scopeValidationCallback.setCarbonGrantType(org.wso2.carbon.identity.oauth.common.GrantType.valueOf(tokReqMsgCtx.
//                                                            getOauth2AccessTokenReqDTO().getGrantType()));
//
//        callbackManager.handleCallback(scopeValidationCallback);
//        tokReqMsgCtx.setValidityPeriod(scopeValidationCallback.getValidityPeriod());
//        tokReqMsgCtx.setScope(scopeValidationCallback.getApprovedScope());
//        return scopeValidationCallback.isValidScope();
    }



    /**
     * TODO
     *
     * You need to implement how to validate the mobile number
     *
     * @param mobileNumber
     * @return
     */
    private boolean isValidMobileNumber(String mobileNumber){

        // just demo validation

        if(mobileNumber.startsWith("033")){
            return true;
        }

        return false;
    }

}
