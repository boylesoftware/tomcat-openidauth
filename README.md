# OpenID Authenticator for Tomcat

This is an extension of the standard [Apache Tomcat](http://tomcat.apache.org) authenticator used for form-based user authentication that also allows users to use [OpenID Authentication](http://openid.net/specs/openid-authentication-2_0.html) to log into the web-applications.

The goal of developing OpenID Authenticator for Tomcat was to allow web-applications that rely on the container to provide form-based user authentication to transparently start using OpenID authentication as one of available options in addition to the standard form-based mechanism. That way, the same application can be deployed in an environment where OpenID authentication is used, or in an environment that only uses regular form-based authentication.

## How OpenID Authentication Works

The complete OpenID Authentication specification can be found [here](http://openid.net/specs/openid-authentication-2_0.html). However, below is a simplified, brief description of OpenID Authentication typical use in a web-application.

With OpenID, authentication of application users is not performed by the application itself but is delegated to a third-party authority called *OpenID provider*. Some examples of such OpenID providers include [Google](http://www.google.com/), [Google Apps](http://www.google.com/intl/en/enterprise/apps/business/), [Yahoo!](http://openid.yahoo.com/), [VeriSign](http://pip.verisignlabs.com/), [myOpenID](http://www.myopenid.com/) and others. An application can support both: authentication of users using their login names and passwords managed locally by the application itself and authentication through one or more OpenID providers.

When an unauthenticated user attempts to access an application resource that requires user authentication, typically, the application shows a special login page. On that page, it offers the user to login either using local application-specific credentials or pick one of supported OpenID providers. If the user picks an OpenID provider, the user's browser is redirected to the login page hosted by that OpenID provider. After receiving and validating user's credentials, the OpenID provider redirects the browser back to the application with a user authentication assertion request and passes an array of special request parameters that allow the application to both identify the user as well as verify the authenticity of the request. Among the positive authentication assertion request parameters there is a value called *claimed ID*, which uniquely identifies the user. This is user's global ID, unique among all OpenID providers. Important property of a claimed ID is that it is possible to discover the responsible OpenID provider.

There are variations on how the application handles the initial request to a protected resource made by an unauthenticated user. For example, the application may not support local authentication, in which case the login page shows only a selection of supported OpenID providers. Or, the application may be configured to work only with one single OpenID provider, in which case the login page does not exist at all and the user is immediately redirected to the OpenID provider. Often, OpenID providers store the fact that the user has been successfully authenticated in the browser's cookies, in which case the OpenID provider does not display the login page either and immediately redirects back to the application with the user authentication assertion.

Another variation is when the application's login page does not show a selection of supported OpenID providers but shows an input field for so called *user-supplied ID*, which is used to tell the application what OpenID provider to use. The user-supplied ID can be an *OpenID provider ID* (a.k.a *OP ID* or *IdP ID*), which is a special kind of URI, using which the application can discover the OpenID provider's *service end-point* URL. Or it can be the user's claimed ID, which can also be used to discover the OpenID provider's service end-point. The service end-point is a URL at which the application communicates with the OpenID provider.

In addition to these two standard user-supplied ID types, the OpenID Authenticator for Tomcat also supports host meta-data URLs. The host meta-data is used to get the OP ID. This is useful with Google Apps, which does not seem to officially publish the OP IDs (even though they are sort of well-known, they supposedly may change, so using host-metadata is more reliable).

Below are examples of some well known values that can be used as user-supplied IDs:

Value                                                                              | Type               | Description
-----------------------------------------------------------------------------------|--------------------|-------------------------------------------------------------------------------
https://<i></i>www.<i></i>google.com/accounts/o8/id                                | OP ID              | Used for regular Google users, such as GMail users.
https://<i></i>www.<i></i>google.com/accounts/o8/id?id=[id]                        | Claimed ID         | Google user claimed ID. The id parameter is a mixed-case alpha-numeric value.
https://<i></i>www.<i></i>google.com/accounts/o8/.well-known/host-meta?hd=[domain] | Host Meta-Data URL | Used for Google Apps accounts. Domain name can be something like "example.com".
http://<i></i>[domain]/openid?id=[id]                                              | Claimed ID         | Claimed IDs assigned to Google Apps users. Domain can be "example.com", and the id parameter is a number containing only decimal digits.
https://<i></i>me.yahoo.com                                                        | OP ID              | Used for Yahoo! users.
https://<i></i>me.yahoo.com/a/[id]                                                 | Claimed ID         | Yahoo! user claimed ID. The id value is mixed-case alphanumeric plus dash.
http://<i></i>[username].myopenid.com                                              | Claimed ID         | myOpenID user claimed ID.

## How OpenID Authenticator for Tomcat Works

Normally, nowadays, Java web-applications that support OpenID authentication implement the authentication logic in the application itself (a filter, a servlet, etc.). The problem with that approach is that user authentication is no longer isolated from the application logic. All modern Java web-application containers support various authentication modules that allow deployment of the same application in different environments and provide it with configurable user authentication services, appropriate for the particular environment. The idea is that user authentication mechanism is supposed to be a part of the application runtime environment and not the application itself.

The goal of developing OpenID Authenticator for Tomcat was to allow web-applications that rely on the container to provide form-based user authentication to transparently start using OpenID authentication as one of available options in addition to the standard form-based mechanism. That way, the same application can be deployed in an environment where OpenID authentication is used, or in an environment that only uses regular form-based authentication.

The OpenID Authenticator for Tomcat extends the functionality behind the standard */j_security_check* call defined in the Servlet specification:

1. When */j_security_check* request is made and there is an *openid_identifier* parameter in the request, the parameter value is taken as the user-supplied identified and OpenID authentication is performed (the browser is redirected to the OpenID provider).
2. If *openid.ns* parameter is present in the request, the request is assumed to be a user authentication assertion callback from the OpenID provider. The authenticator verifies the authenticity of the request, finds the user in the configured realm and, if all correct, marks the session as authenticated and passes control to the application (redirects to the originally requested protected resource, or the application landing page if session has expired since the original request was made).
3. Otherwise, regular form-based authentication is performed using standard *j_username* and *j_password* request parameters.

## Authenticator Usage

### Download

You can download the latest authenticator JAR from:

https://www.boylesoftware.com/maven/repo-os/com/boylesoftware/catalina/authenticator/openid/openidauth/

Also, the project is hosted at GitHub at:

https://github.com/boylesoftware/tomcat-openidauth

### Installation

Place the authenticator JAR in *$CATALINA_BASE/lib*, or use some other way to include the JAR in the Tomcat's class path.

### Configuration

#### Authenticator

Typically, the authenticator configuration is performed in the web-application's [context configuration](http://tomcat.apache.org/tomcat-8.0-doc/config/context.html). To make Tomcat use the OpenID authenticator, add the authenticator valve to the context XML:

```xml
<Valve className="org.bsworks.catalina.authenticator.openid.OpenIDAuthenticator"/>
```

The authenticator supports the following optional properties:

* **xriProxyURL**

	URL of the XRI proxy resolver. Claimed IDs and OpenID provider IDs sometimes can be represented by an [XRI](http://en.wikipedia.org/wiki/XRI). In that case, the XRI needs to be *resolved* in order to discover the service end-point URL. For the XRI resolution, the authenticator relies on an external service called *XRI proxy resolver*. The default is "http://<i></i>xri.net/". It is rarely needs to be overridden.

* **hostBaseURI**

	Virtual host base URI. When the authenticator redirects the browser to the OpenID provider, it needs to specify the URL of the page, to which the OpenID provider must return after user authentication. This is so called *return URL*. The **hostBaseURI** property is used to construct the return URL. It must include and protocol (should be always HTTPS), host and, if needed, port, but not the context path. It also *must not* end with a slash. For example, "https://<i></i>www.<i></i>example.com". If this property is not specified, the authenticator will make an attempt to construct the URI based on the current request. In majority of cases, the authenticator can construct the correct URI, so this property rarely needs to be overridden.

* **singleProviderURI**

	ID of the single OpenID provider. When specified, all authentication is delegated to single identified OpenID provider and no other provider is allowed to make authentication assertions. This also makes the authenticator completely skip the application login screen. As soon as an unauthenticated user makes a request to a protected resource, the authenticator immediately redirects the browser to the OpenID provider. The value of this property can be a URI, an XRI, or it can be a URL of the host meta-data that contains the OpenID provider URI.

* **allowedClaimedIDPattern**

	Regular expression pattern for allowed claimed IDs. If this property is specified, positive authentication assertions will be accepted only if the claimed ID of the authenticated user matches the pattern. Note, that if **loginNameAttributeType** property is set, this property *must* also be set. This is a security feature that prevents a hacker running an OpenID provider that supplies login names selected by the **loginNameAttributeType** property. Claimed IDs, on the other hand, cannot be forged, because the authenticator verifies if the OpenID provider making the authentication assertion call is responsible for the supplied claimed ID.

* **loginNameAttributeType**

	[OpenID Attribute Exchange](http://openid.net/specs/openid-attribute-exchange-1_0.html) extension attribute type identifier of the attribute used as the application user login name. The value of the attribute, sent back to the application with the positive authentication assertion call, is used as the user name to lookup the user in the configured realm. For example, to use user e-mail address as the login name, this attribute should be set to "http://<i></i>axschema.org/contact/email". If not specified, the claimed ID is used as the login name. Note, that if this property *is* specified, the **allowedClaimedIDPattern** *must* be also specified.

* **httpConnectTimeout**

	Timeout in milliseconds for making HTTP connections to the third-parties in the OpenID authentication protocol. This is used when the authenticator talks directly to the servers participating in the OpenID protocol. See description [here](http://docs.oracle.com/javase/6/docs/api/java/net/URLConnection.html#setConnectTimeout(int)). The default is 5000 milliseconds.

* **httpReadTimeout**

	Timeout in milliseconds for reading HTTP data from the third-parties in the OpenID authentication protocol. This is used when the authenticator talks directly to the servers participating in the OpenID protocol. See description [here](http://docs.oracle.com/javase/6/docs/api/java/net/URLConnection.html#setReadTimeout(int)). The default is 5000 milliseconds.

* **browserRedirect**

	Flag telling the authenticator if it should delegate sending the authentication request to the OpenID provider to the user's browser. When the authenticator receives the initial */j_security_check* request with the *openid_identifier* in it, thus asking it to perform OpenID authentication, if this flag is "false", the authenticator builds an authentication request, sends it directly from the server-side to the OpenID provider and expects the OpenID provider to return a redirect response, which is then relayed back to the browser making the browser go to the OpenID provider's login page. Not all OpenID providers return a redirect response upon receiving an authentication request (e.g. myOpenID). Therefore, if the **browserRedirect** flag is "true", which is the default, the authenticator builds special HTML with a form representing the authentication request and a JavaScript that automatically submits the form as soon as it is loaded. The HTML is then sent back to the browser in a regular HTTP response and the browser makes the authentication request to the OpenID provider on its own.

* **developmentMode**

	If "true", the authenticator is switched to the special development mode. In this mode, it never actually redirects to the OpenID provider. Instead, when an authentication request is made, it shows a built-in fake login page where the developer can enter a user login name and the authenticator will make the session authenticated for the specified user.

Here is an example of the authenticator configuration using e-mail address as the user login name and Google as the single OpenID provider:

```xml
<Valve className="org.bsworks.catalina.authenticator.openid.OpenIDAuthenticator"
       singleProviderURI="https://www.google.com/accounts/o8/id"
       loginNameAttributeType="http://axschema.org/contact/email"
       allowedClaimedIDPattern="https://www\.google\.com/accounts/o8/id\?id=.+"/>
```

All properties of a standard Tomcat form authenticator, which the OpenID authenticator extends, can be used as well. See http://tomcat.apache.org/tomcat-8.0-doc/api/org/apache/catalina/authenticator/FormAuthenticator.html for the form authenticator properties.

#### Realm

The authenticator *must be* configured with a special realm implementation `org.bsworks.catalina.authenticator.openid.OpenIDRealm`. This is an extension of the standard Tomcat [combined realm](http://tomcat.apache.org/tomcat-8.0-doc/realm-howto.html#CombinedRealm). The first sub-realm in the combined realm is used only for OpenID authentication. The rest, if present, is used for regular form-based authentication according to the standard combined realm rules.

The first sub-realm &mdash; the OpenID realm &mdash; is special. Since the verification of user credentials is performed by the OpenID provider, the realm is not used for that. It is used only for verification that the authenticated by the OpenID provider user is known to the application (that is the user account exists) and, when applicable, it also provides the application-specific user roles.

However, due to limitations of the Tomcat API, the authenticator still needs to provide the realm with the user password when looking up the user. The OpenID authenticator implementation always uses the login name as the password, so the realm needs to be configured accordingly. For example, if a [DataSourceRealm](http://tomcat.apache.org/tomcat-8.0-doc/realm-howto.html#DataSourceRealm) is used, both login name and password attributes can point to the same column in the database table that stores user accounts. For example:

```xml
<Realm className="org.bsworks.catalina.authenticator.openid.OpenIDRealm">
    <!-- OpenID authentication -->
    <Realm className="org.apache.catalina.realm.DataSourceRealm"
           dataSourceName="jdbc/authority"
           userTable="users" userNameCol="user_name" userCredCol="user_name"
           userRoleTable="user_roles" roleNameCol="role_name"/>
    <!-- Form-based authentication -->
    <Realm className="org.apache.catalina.realm.UserDatabaseRealm"
           resourceName="UserDatabase"/>
</Realm>
```

Or, if a [JNDIRealm](http://tomcat.apache.org/tomcat-8.0-doc/realm-howto.html#JNDIRealm) is used with users stored in an LDAP directory, the login name and password can point to the same entry property:

```xml
<Realm className="org.bsworks.catalina.authenticator.openid.OpenIDRealm">
    <Realm className="org.apache.catalina.realm.JNDIRealm"
           connectionURL="ldap://localhost:389"
           connectionName="cn=Manager,dc=mycompany,dc=com"
           connectionPassword="secret"
           userPattern="uid={0},ou=people,dc=mycompany,dc=com"
           userPassword="uid"
           roleBase="ou=groups,dc=mycompany,dc=com"
           roleName="cn"
           roleSearch="(uniqueMember={0})"/>
</Realm>
```

Because the password in the OpenID realm is always known (it is always the user's login name), the OpenID realm is never used for regular form-based authentication. To allow local form-based user authentication second, third, etc. sub-realms need to be defined (like in the DataSourceRealm example above).

### Web-Application

#### Deployment Descriptor

The OpenID authenticator is compatible with the standard Tomcat form-based authenticator. That means that the web-application can be configured exactly the same way as for form-based authentication. For example, in the application's *web.xml* there could be the following block:

```xml
<login-config>
    <auth-method>FORM</auth-method>
    <form-login-config>
        <form-login-page>/WEB-INF/jsp/login.jsp</form-login-page>
        <form-error-page>/WEB-INF/jsp/login.jsp</form-error-page>
    </form-login-config>
</login-config>
```

In this example, the same */WEB-INF/jsp/login.jsp* is used both for the login page and the login error page. For the form-based authentication, the error page is displayed, for example, when the login name and/or password is invalid. For the OpenID authentication, the error page is displayed, for example, when the OpenID provider has successfully authenticated the user and redirected the browser back to the application, but the authenticator was not able to find the authenticated user in the realm. If the single OpenID provider mode is configured, it does not make sense to show the user a login page. This is where the application may need to be programmed in an OpenID authenticator aware way. Instead of showing the login form with user name and password fields, the error page should simply inform the user about the authentication problem and suggest to login as a different user.

#### Login Page

The login page, and possibly the login error page, are the only parts of the application that may need to be aware of the OpenID authenticator. The application can use an additional context parameter to tell it if it is running in an environment with the OpenID authenticator, or if only the standard form-based authenticator is used. For example, below is a sample login page JSP, which is also used as the login error page:

```jsp
<!DOCTYPE html>
<html>
  <head>
    <title>Login</title>
  </head>
  <body>
    <%
    String requestURI = (String) request.getAttribute("javax.servlet.forward.request_uri");
    if (requestURI == null)
        requestURI = request.getRequestURI();
    if (requestURI.endsWith("/j_security_check")) {
    %>
    <div style="color: red;">Invalid login</div>
    <%
    }
    %>
    <form action="j_security_check" method="post">
      <%
      String authMode = request.getServletContext().getInitParameter("authMode");
      if (authMode == null)
          authMode = "form";
      if (authMode.endsWith("openid")) {
      %>
      OpenID Login:</br>
      User-Supplied Identifier: <input type="text" name="openid_identifier"/><br/>
      <%
      }
      if (authMode.startsWith("form")) {
      %>
      Local Login:<br/>
      Login Name: <input type="text" name="j_username"/><br/>
      Password: <input type="password" name="j_password"/><br/>
      <%
      }
      %>
      <input type="submit"/>
    </form>
  </body>
</html>
```

In this example, context parameter *authMode* determines what authentication methods are used by the application. If it is "form" or unspecified, only form-based authentication is used. If it is "openid", only OpenID authentication is used. If it is "form_openid", both form-based and OpenID authentication are used.

### Debugging

It is useful to enable logging when trying to debug problems with the authentication. The authenticator uses Tomcat's JULI logging. The following statements can be added to Tomcat's *logging.properties* if:

```ini
com.boylesoftware.catalina.authenticator.openid.level = FINE
org.apache.catalina.authenticator.level = FINE
org.apache.catalina.realm.level = FINE
```

## Logout

Curiously enough, groups that develop various standards for user sign in rarely touch the topic of user sign out. The OpenID specification is not an exception.

In Servlet specification, there is a logout method on the request object. In Tomcat, internally, this method also calls a logout method on the authenticator. However, this API does not allow the authenticator to anyhow influence the HTTP response sent back to the user upon submitting the logout action. In order to sign out from an OpenID provider, however, it is usually necessary to redirect the user's browser to a specific page hosted by the OpenID provider. If that is not done, the user can logout from the web-application but stay logged in with the OpenID provider. After such "logout", if the user attempts to access the application, the session will be successfully re-authenticated again without the user entering any credentials. Also, such "logout" creates a false impression for the user of being logged out from the OpenID provider. Someone else may access the browser later and go to the OpenID provider's services being authenticated as the previous user.

Until these issues are resolved, either the application has to include OpenID provider-specific logic for user logout, or the user must remember to first logout directly from the OpenID provider and only then logout from the web-application.

## More on OpenID

* [OpenID Foundation](http://openid.net/)
* [OpenID Authentication 2.0 Specification](http://openid.net/specs/openid-authentication-2_0.html)
* [Federated Login for Google Account Users](http://developers.google.com/accounts/docs/OpenID)
* [OpenID Federated Login Service for Google Apps](http://developers.google.com/google-apps/sso/openid_reference_implementation)
