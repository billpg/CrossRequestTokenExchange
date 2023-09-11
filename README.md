# Cross Request Token Exchange
An authentication exchange between two web services.

## The elevator pitch.

Alice and Bob are normal web servers with an API.
- (Alice opens an HTTPs request to Bob.)
- "Hey Bob. I want to use your API but I need a Bearer token."
  - (Bob opens a separate HTTPS request to Alice.)
  - "Hey Alice, have this Bearer token."
  - "Thanks Bob."
- "Thanks Alice."

Did you notice what didn't happen?

Neither side needed a pre-shared key, a shared secret nor a place to securely store them. Both machines are web servers with TLS already set up and this is what enables the exchange to work.

When you make an HTTPS request, thanks to TLS you can be sure who you are connecting to, but the service receiving the requst can't be sure who the request is coming from. By using **two separate** HTTPS requests in opposite directions, the two web servers may perform a brief handshake and exchange a *Bearer* token.

### What's a Bearer token?

A Bearer token is string of characters. It could be a signed JWT or a string of randomness. If you know what that string is, you can include it any web request where you want to show who you are. The token itself is generated (or "issued") by the service that will accept that token later on as proof that you are who you say you are, because no-one else would have the token. 

```
POST /api/some/secure/api/
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJuZ2d5dSI6Imh0dHBzOi8vYmlsbHBnLmNvbS9qMS8ifQ.nggyu
{ "Stuff": "Nonsense" }
```

That's basically it. It's like a password but very long and issued by the remote service. If anyone finds out what your Bearer token is they would be able to impersonate you, so it's important they go over secure channels only. Bearer tokens typically (but not always) have short life-times and you'd normally be given an expiry time along with the token itself. Cookies are a common variation of the Bearer token.

The exchange in this document describes a mechanism for a server to request a Bearer token from another server in a secure manner.

## The exchange in a nutshell.

There are two participants in this exchange:
- The **Initiator** is requesting a Bearer token.
- The **Issuer** issues that Bearer token back to the Initiator.

They connect to each other as follows:
1. The Initiator opens a POST request to the Issuer's API to trigger the exchange, including an HMAC key.
2. The Issuer, keeping that first request open, opens a separate POST request to the Initator's API.
    - This request will contain a new Bearer token for the Initiator, with a signature using the HMAC key from the first request.
3. The Initator checks the signature and closes the second POST request with a 204 code, signalling it accepts the supplied token.
4. The Issuer finally closes the first POST request with a 204 code, signalling the issued token is now ready to be used.

We'll now look at each step in detail.

### The Initiate Request

The process is started by the Initiator, who needs a Bearer token from the Issuer. The Issuer will open a new POST request to the URL that the Issuer documented a URL for the Initiator to use. This POST request includes a JSON request body as described below.

The JSON must have the following string properties, all required.
- `CrossRequestTokenExchange`
  - This indicates the client is attempting to use the CrossRequestTokenExchange process and the version. The value "DRAFTY-DRAFT-4" refers to the version of this exchange described in this document.
- `ExchangeId`
  - A GUID value identifying this exchange. The subsequest POST request will include this ID.
- `HmacKey`
  - A HMAC key that the Issuer will later use to sign the Bearer token, confirming that it came from the expected source.
  - The value must consist of exactly 256 bits of cryptographic quality randomness encoded in base64.
  
The request must not use any `Authorization` or `Cookie` headers.

For example:
```
POST https://issuer.example/api/initiate?initiator_user_id=123456
Content-Type: application/json
{
    "CrossRequestTokenExchange": "DRAFTY-DRAFT-4",
    "ExchangeId": "C4C61859-0DF3-4A8D-B1E0-DDF25912279B",
    "HmacKey": "mj4i5dRcagrBzHOmIb8VryPU0zn8Z65T+tiakAJGOaI="
}
```

The Issuer's web service will receive this request and if there are any problems, will return an immediate error response. If all is well, it will keep this initial request open until the exchange has concluded.

### The Issue Request

While keeping the initial POST request open, the Issuer's web service (receiving that request) will open a new POST request back to the Initiator, using the URL agreed in advance. This second request is to pass the newly generated Bearer token itself to the Initiator.

The Issuer will generated the token (not yet knowing for sure the initial request was genuine), sign the token using the HMAC key supplied in the initial request and include both in the second POST request.

Because the Issuer is sending the Bearer token to a pre-agreed POST URL over HTTPS, they can be sure no-one else will have eavesdropped on that transaction. Because the request body includes an HMAC signature based on that HMAC key that no-one else knows, the Initiator can be sure the token genuinely came from the Issuer.

The JSON request body is made up of the following string value properties, all of which are required.
- `ExchangeId`
  - The GUID from the original Initiate request body that identifies this exchange.
- `BearerToken`
  - This is the requested Bearer token. It must consist only of printable ASCII characters.
- `ExpiresAt`
  - The UTC expiry time of this Bearer token in ISO format. (yyyy-mm-ddThh:mm:ssZ)
- `BearerTokenSignature`
  - The HMAC signature of the BearerToken value's ASCII bytes, signed using HMAC-SHA256 with the `HmacKey` from the original Initiate request.
  - The 256 bit HMAC signature encoded in base64.

The request must not include any `Authorization` or `Cookie` headers.

For example:
```
POST https://initiator.example/api/Issue?issuer_user_id=12345
Content-Type: application/json
{
    "ExchangeId": "C4C61859-0DF3-4A8D-B1E0-DDF25912279B",
    "BearerToken": "Token_09561454469379876976083516242009314095393951",
    "ExpiresAt": "2023-10-24T14:15:16Z",
    "BearerTokenSignature": "CLx8KSN7z+QSwob4ZOApIB7qvYD1KiwxA+qkDrZOlJ4=",
}
```

### Initiator, responding to the Issue request

If the Intiator web service finds the Bearer token it has received to be acceptable (including checking the HMAC signature), it may respond to this second request with a 204 code to indicate it accepts the supplied token and that the issuer should (if needed) activate the token.

Any error response indicates to the Issuer caller that the Initator doesn't accept the supplied token. This could mean that it didn't make the original request or that the HMAC signature verification failed, or simply an internal issue preventing the complete processing of the request. The Issuer, receiving such an error response should discard or otherwise deactivate the token.

Even if accepting the supplied token, the Initiator should not actually use the token until the entire exchange has complted by the Issuer responding to the first Initiate request with a success response.

### Issuer, responding to the Initiate request.

Once the Initiator has indicated it accepts the supplied token, the Issuer needs to finally indicate the issued token may now be used by finally closing down the Initiate request that has been kept open with a 204 response. This is a signal from the Issuer that any neccessary activation has completed and the token is now ready to be used.

If there is an error when attempting to activate the newly issued token, the Issuer may indicate this by returning an error response to the Initiator. The Initiator should discard the newly issued token in this event. Any error responses shoudl enough detail in the response body to assist a developer in fixing the problem.

## Version Negotiation

The intial request JSON includes a property named `CrossRequestTokenExchange` with a value `DRAFTY-DRAFT-4`, specifying the version of this protocol the client is using. As this is the first (and so far, only) version, all requests should use only this string. 

If a request arrives with a different and unknown string value to this property, the service should respond with a `400` (bad request) response, but with a JSON body that includes a property named `AcceptVersion`, listing all the supported versions in a JSON array of strings. The response may contain other properties but this property at the top level of the JSON response is set aside for version negotiation.

If there is a future version of this exchnage the Initiator prefers to use, it should specify its prefered version in that request and leave it to the Isser service to respond with the list of versions it understands. At this point, the Initiator should select most preferable version on the list and repeat the Initiate request with that version.

```
POST https://bob.example/api/BearerRequest
{ "CrossRequestTokenExchange": "NEW-FUTURE-VERSION-THAT-YOU-DONT-KNOW-ABOUT", ... }

400 Bad Request
{ 
    "Message": "Unknown version.",
    "AcceptVersion": [ "DRAFTY-DRAFT-4" ] 
}
```

# Case Studies

## A Saas API.

**saas.example** is a website with an API designed for their customers to use. When a customer wishes to use this API, their code must first go through this exchange to obtain a Bearer token. The service publishes a document for how their customers including the URL to POST Initiate requests to. (`https://saas.example/api/login/crte?userId=id`, filling in their unique user ID.)

**Carol** is a customer of Saas. She's recently signed up and has been allocated her unique user id, 12. She's logged into the Saas customer portal and browsed to their authentiation page. Under the CRTE section, she's configued her account that `https://carol.example/saas/crte-receive-token` is her URL for the Issuer to send the new Bearer token to, where she's implemented a handler.

Time passes and Carol's server needs to make a request to the Saas API. As the server has no Bearer tokens, the code makes a POST request to the documented API:
```
POST https://saas.example/api/login/crte?userId=12
Content-Type: application/json
{
    "CrossRequestTokenExchange": "DRAFTY-DRAFT-4",
    "ExchangeId": "F952D24D-739E-4F1E-8153-C57415CDE59A",
    "HmacKey": "NZVyqSyBlVoxBN64YA69i9V2TgzAe6cgxt2uN08BZAo="
}
```

The Saas website code looks up user 12 and finds an active user with CRTE configured. (If CRTE isn't configured, it would immediately respond with an error.) At this point, the Saas service does not yet know if the Initiate request came from the real Carol, yet. 

The Saas service duly generates a Bearer token and signs the token using HMAC with the key supplied in the initial request. It does not yet save this token to it's own database but holds it in memory until such time the providence of Carol as the Initiator can be confirmed.

Using the URL Carol configured earlier, the Saas web service software opens up a new HTTPS request:
```
POST https://carol.example/saas/crte-receive-token
Content-Type: application/json
{
    "ExchangeId": "F952D24D-739E-4F1E-8153-C57415CDE59A",
    "BearerToken": "Token_41401899608293768448699806747291819850802711",
    "ExpiresAt": "2023-10-24T14:15:16Z",
    "BearerTokenSignature": "MlqLjJzX7X4Ttf7fOHfoxH+Tyc9uigebAqJrR398h1M=",
}
```

As Carol really is the Initiator, her web service can look up the supplied ExchangeId and find the Initiate request it opened earlier. It has a Bearer token but it doesn't yet know if this is the genuinely the Saas service making an Issue request yet. To check this, it performs the same HMAC operation with the HMAC key it supplied in the initial request. Happy that everything is verified, the service stores the Bearer token but it can't use the token just yet.

To confirm that all is well, Carol's web service closes the Issue request by sending a 204 status, indicating that it accepts the Bearer token. The Saas web server writes the token it generated into the database instead of only holding it in memory. The Saas service can finally closes the Initiate request with a 204, this time signalling that Carol may now use the Beaer token it issued.

```
GET https://saas.example/api/status.json
Authorization: Bearer Token_41401899608293768448699806747291819850802610
```

## Webhooks

The authentication requests don't always go from Carol to Saas. Occasionally, the Saas service will need to call back to Carol's web service to deal with an event. When this happens, Carol's web service needs to be certain the request is coming from Saas and not someone else trying to get privilendged information from Cartol's Webhook handler.

To deal with this, as well as comfiguring a Webhook URL, Carol has also configured her own Initiate end-point, should the Saas service need to authenticate itself.

Time passes and the Saas service needs to call Carol's API to make a decision, but it doesn't have a valid Bearer token yet. It looks up the URL she configured and makes an HTTPS request:
```
POST https://carol.example/saas/crte-generate-token-for-webhook
Content-Type: application/json
{
    "CrossRequestTokenExchange": "DRAFTY-DRAFT-4",
    "ExchangeId": "B405DE48-36F4-4F42-818C-9BE28D6B3832",
    "HmacKey": "3og+Au+MkBPQDhd60RT50e2KnVx86xPI1SLUVtlUa+U="
}
```

Carol's web service opens a new HTTPS request back to the Saas web site and in a similar way to before, it populates this new request with a Bearer token it had generated and an HMAC signature. The Saas API documents that the webhook CRTE Issue requests should go to `https://saas.example/api/issue-crte?user_id=id` with the user's id added to the query string parameter.
```
POST https://saas.example/api/issue-crte?user_id=12
Content-Type: application/json
{
    "ExchangeId": "B405DE48-36F4-4F42-818C-9BE28D6B3832",
    "BearerToken": "Token_51968399312599211031848828204659448702950691",
    "ExpiresAt": "2023-10-24T14:15:16Z",
    "BearerTokenSignature": "zmalbMtYLNvzNQisyQJaEtwVqfb73+BG9kO/3a8Qv98=",
}
```

The Saas service first acknowledes acceptance of the token by returning 204 to its incoming HTTPS request. Carol's web service handler acknowledges the acknowledgment by also responding to its incomming request with 204.

With a token that's been confirmed valid, the Saas service may now make its Webhook call.

```
POST https://carol.example/saas/webhook
Authorization: Bearer Token_51968699312599211031848828204659448702950696
Content-Type: application/json
{ "IsThisAWebhook?": true }
```

## Anticipated Asked Questions

### What's wrong with keeping a pre-shared secret long term?
They require management and secure storage. If we've already made the investment in configuring TLS on both sides, why not utilize that and get rid of the pre-shared secrets?

### I don't have a web server.
Then this exchange is not for you. It works by havng two web servers make requests to each other.

### I'm not a web server, but I have one on the other side of the Internet.
Can you set up that web server to handle requests on your behalf? You would need a secure channel between yourself and the web server to pass POST requests and responses along.

### I don't have my own web server, but could I use an external service to receive the Issue request instead?
As long as you trust that service and you have a secure channel between you and teh service. If you don't trust it, or it's a service that publishes the contents of all incoming POST requsts, that would not be a suitable service for this exchange. The body of the Issue request will be secured thanks to TLS, but TLS only secures the traffic between the two end-points, not any additional step beyond the end-points.

### What if I want to use a public service I don't neccessarily trust?
Exactly to support this arrangemt, an earlier draft of this exchange included an AES key alongside the HMAC key. I ommitted it for this version to simplify it, uncertain of its value. I am open to be persuded that this would be a useful addition to this exchange.

With this in place, if you (as the Initiator) make a POST request to an Issuer directly, you'd supply an AES key and IV as well as an HMAC key, all freshly generated from a cryptographic-quality random source. The Issuer would generate the Issue request as before, but instead of sending it in the clear (albetit inside TLS), the Issue request would be AES encrypted as well as HMAC signed. Onlyyour code would be able to check the signature and decrypt the token inside.

### Could an untrusted third party also handle being an Issuer?
Perhaps, but if you can accept Bearer tokens once this exchange has completed, then you must already have a web server so you don't need a third party service to do this bit for you.

If that statement is wrong, open an issue and persude me.

### Isn't the HmacKey key a pre-shared secret?
If you like, but the scope is very different. For the Initiator, the bytes can be generated from the system random number generator onky when needed and the key needs only to be stored in local memory without needing to store it externally. Once the exchange has completed the HMAC key can be discarded.

### How long should a bearer token last until expiry?
Up to you but (finger in the air) I'd go for an hour. If the exchange takes too long, remember you can do it in advance and have the Beaerer token ready if needed.

### What if either web service uses a self-signed TLS certificate or one signed by an untrusted root?
If a connection to an untrusted TLS certifcate is found, abandon the request and maybe log an error. 

Since this exchange relies on a pre-existing relationship, you could perhaps allow for "pinned" TLS certificates to be configured.

### Is the HMAC key needed?
The risk of ignoring the HMAC signature is that an attacker could supply a bad Bearer token, or one belonging to someone else. If that's not a problem then you could ignore the HMAC signature but why not check it anyway?

### What if generating a token is expensive?
This is another feature I since removed from an earlier draft of theis document and I'm open to be persuaded that it should be put back. The Initiator could, instead of making an "Issue" request, send a "Verify" request first. At this step, the Issuer is asking the Initiator to confirm the request is genine, including a short message signed with the HMAC to confirm the request is itself genuine.

I removed that step in early development to simplify the exchange. Having just two web requests, one in each directon, had a nice symmetry. The main consideration was the realisation that issuing a token is fairly cheap. Both JWT and random strings can be generated without much computing power, especially compared to signing an HMAC and making another POST request.

As the Issuer has a opportunity (in the response to the initial POST request) to withdraw an issued token, the Issuer could defer activating the generated token (perhaps saving it to a database) until after the Initiator has accepted it.

### Why do the two particpants have to a pre-existing relationship?
This is another feature I removed since writing early drafts. 

I wondered if this exchange could work as the only authentication system needed. I imagined signing up for some kind of service and registering by pasting in my own website domain as the only means of authentication. The service would go talk to the website on my domain, exchange tokens and I'm logged in. The Intiate request would include a URL to return the signed token, but the request was otherwise 

This appealed to me, but there was a problem with that approach. Any doer-of-evil could come along to a website that implemented this exchange and cause that service to make a POST request to any URL they wanted on any domain. You couldn't control the request body but that might be enough to cause a problem. To resolve this, I wrote into the draft specification that the claimed URL should first be confirmed by GET-ing a `/.well-known/` file that lists all the URLs that implement this API.

Wanting to simplify the basic specification, I instead changed this step to requiring a prior relationship and for the URL for the POST request to be pre-configured. Any complexity of establishing a relationship is set aside.

I am open to discussing ways of adding mechanisms to use this method without a prior relationship.

### What if an attacker attempts to eavesdrop or spoof either request?"
The attacker can't eavesdrop because TLS is securing the channel.

### What if an attacker sends a fake Initiate request to an Issuer?
The Issuer will generate a unasked-for Bearer token and send it to the real Initiator, who will reject it because it wasn't expecting one.

### Does it matter if the GUID is predictable?
No. The security of the exchange is based on HMAC and TLS.

### What if an attacker sends a fake Issue request?
If the Initiator isn't expecting an Issue request, they won't have a HMAC key to check the signature, so can reject the request.

If the Initiator *is* expecting an Issue request, they will be able to test it came from the genuine Issuer by checking the signature. The attacker won't know how to generate a signature without the unpredictable Initiator's key.

### What if an attacker floods either particpants URLs with many fake requests?
Suppose an attacker pretends to be a genuine Initiator and floods a known Issuer with many fake Initiate requests. On this situation, the Issuer will generate and sign many tokens and pass them all to the real Initiator. The Initiator will reject them all because none of them will correspond to a known HMAC key.

While the exchange prevents tokens from leaking to an attacker, the fact that a request will trigger a second request might be used as a denial-of-service attack. For this reason, it may be prudent for an Issuer to track IP address blocks with a history of making Initiate requets that are not completed and reject Initiate requests that originate from these blocks.

Similairly, as IP address tend to be stable, it may be prudent to record the IP addresses that successful exchanges have originated from in the past. Limit the zone of all other addresses to enough for an Initiator to unexpectantly move to a new IP but not so much that a flood opens up.

The Initiator's web service might also be flooded with fake Issue requests, but in this case because an Issue request doesn't trigger a second request, normal methods to deflect denial-of-service attackers would be sufficient.

It may also be prudent to keep the POST URLs secret, so attackers can't send in a flood of fake requests if they don't know where to send them. As this would only be a method to mitgate a denial-of-service atttack, the secret URL doesn't have to be treated as secret needing secure storage. The URL could be set in a unencrypted config file and if it does leak, be replaced without urgency at the participant's convenience. The security of the exchnage relies on TLS and the HMAC signature, not the secrecy of the URLs.
