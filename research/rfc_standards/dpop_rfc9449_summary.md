DPoP — OAuth 2.0

[![OAuth](/images/oauth-logo-square.png)
oauth.net](/)

Featured Video Course: [The Nuts & Bolts of OAuth 2.0](https://www.udemy.com/course/oauth-2-simplified/?referralCode=B04F59AED67B8DA74FA7)

[Home](/)
[Getting Started](/getting-started/)
OAuth 2.0
[OAuth 2.0 Overview](/2/)
Core Concepts

* [Access Tokens](/2/access-tokens/)
* [Refresh Tokens](/2/refresh-tokens/)
* [Scope](/2/scope/)
* [Client Types](/2/client-types/)
* [Client Authentication](/2/client-authentication/)
* [Bearer Tokens](/2/bearer-tokens/)
Grant Types

* [Overview](/2/grant-types/)
* [Authorization Code](/2/grant-types/authorization-code/)
* [PKCE](/2/pkce/)
* [Client Credentials](/2/grant-types/client-credentials/)
* [Device Code](/2/grant-types/device-code/)
* [Refresh Token](/2/grant-types/refresh-token/)
* [LegacyImplicit](/2/grant-types/implicit/)
* [LegacyPassword](/2/grant-types/password/)
Tokens & Keys

* [JWT Access Tokens](/2/jwt-access-tokens/)
* [Token Introspection](/2/token-introspection/)
* [Token Revocation](/2/token-revocation/)
* [Token Exchange](/2/token-exchange/)
* [JSON Web Token](/2/jwt/)
Security

* [Security BCP](/2/oauth-best-practice/)
* [Threat Model](/2/security-considerations/)
* [DPoP](/2/dpop/)
* [Mutual TLS](/2/mtls/)
* [PAR](/2/pushed-authorization-requests/)
App Types

* [Browser-Based Apps](/2/browser-based-apps/)
* [Native Apps](/2/native-apps/)
* [Device Flow](/2/device-flow/)
Discovery

* [Server Metadata](/2/authorization-server-metadata/)
* [Dynamic Registration](/2/dynamic-client-registration/)
* [Registration Management](/2/dynamic-client-management/)
[OAuth 2.1](/2.1/)
Reference
[All Specs](/specs/)
[Code & Libraries](/code/)
[Security](/security/)
Learn
[Articles](/articles/)
[Videos](/videos/)
[Books](/books/)
[Events](https://events.oauth.net/)
About
[FAQ](/faq/)
[Consulting](/consulting/)
[Credits](/about/credits/)
[Community](/about/community/)

1. [OAuth 2.0](/2/)
2. DPoP

DPoP — Demonstrating Proof of Possession
----------------------------------------

[RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)
Published
[rfc-editor.org/rfc/rfc9449](https://www.rfc-editor.org/rfc/rfc9449)

DPoP cryptographically binds an access token to the client's private key. Even if the token is stolen, an attacker can't use it without the corresponding key.

**When to use this**
Use DPoP when you need sender-constrained tokens — typically in high-security deployments like financial APIs or when implementing [FAPI 2.0](/fapi/). DPoP is required or recommended by FAPI 2.0 and provides stronger security than plain Bearer Tokens without requiring mutual TLS infrastructure. It works well for both browser-based and native app clients.

DPoP works by having the client generate an asymmetric key pair and send a signed JWT proof with each request. The authorization server binds the issued access token to the public key. The resource server verifies the proof on each request, ensuring only the client with the matching private key can use the token.

### See also

* [Bearer Tokens](/2/bearer-tokens/) — the simpler alternative (no key binding)
* [Mutual TLS](/2/mtls/) [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705) — certificate-based sender-constraining

Found an error or want to add something?
[Edit this page on GitHub →](https://github.com/aaronpk/oauth.net/blob/main/public/2/dpop/index.php)
·
[Merch](https://shop.oauth.net/)