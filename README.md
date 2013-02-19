OpenID Authenticator for Tomcat
==========

This is an extension of the standard Apache Tomcat authenticator used for
form-based user authentication that also allows users to use OpenID
Authentication to log into the web-applications.

The goal of developing OpenID Authenticator for Tomcat was to allow
web-applications that rely on the container to provide form-based user
authentication to transparently start using OpenID authentication as one of
available options in addition to the standard form-based mechanism. That way,
the same application can be deployed in an environment where OpenID
authentication is used, or in an environment that only uses regular form-based
authentication.

For more information on the authenticator see Wiki page at:
https://www.boylesoftware.com/wiki/index.php/OpenID_Authenticator_for_Tomcat