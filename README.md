 # Seges.Samples.JavaSaml2TokenValidator
Sample demonstrating SAML 2 token validation in Java

- replace the token with a non-expired one signed by the IdP 
 - e.g. by intercepting ADFS RSTR with SAML 2 token inside and extracting <Assertion /> xml
- replace the signing cert
 - e.g. export ADFS signing certificate public key in Base64 encoded format
