##ALOSRPAuth

Alexey Yachmenov <[aloner.brn@gmail.com](mailto:aloner.brn@gmail.com)>

Objective-C implementation of [Secure Remote Password protocol](http://srp.stanford.edu/) (SRP-6a). Based on [csrp](https://github.com/cocagne/csrp) library.

##SRP Overview

SRP is a secure password-based authentication and key-exchange protocol. It solves the problem of authenticating clients to servers securely, in cases where the user of the client software must memorize a small secret (like a password) and carries no other secret information, and where the server carries a verifier for each user, which allows it to authenticate the client but which, if compromised, would not allow the attacker to impersonate the client. In addition, SRP exchanges a cryptographically-strong secret as a byproduct of successful authentication, which enables the two parties to communicate securely.

##Usage Example
-------------

```objectivec
// private constants
NSString *N = @"115b8b692e0e045692cf280b436735c77a5a9e8a9e7ed56c965f87db5b2a2ece3";
NSString *g = @"02";
ALOSRPPrivateData *privateData = [ALOSRPPrivateData privateDataWithN:N g:g];

// init autentification with constants & login, password
ALOSRPAuth *auth = [[ALOSRPAuth alloc] initWithPrivateData:privateData
                                                     login:self.loginField.text
                                                  password:self.passwordField.text];
[auth startAuthorization];

// generate A
NSString *aBytes = [auth aBytesBase64];
if (auth.error) return;

// TODO: here we send login, A and receive salt & B from server
NSData *salt = [[NSData alloc] initWithBase64EncodedString:@"VgUNyWfG/ZzavL7JEUdwCsto7+w=" options:NSDataBase64DecodingIgnoreUnknownCharacters];
NSData *bBytes = [[NSData alloc] initWithBase64EncodedString:@"AunqLMG6ymWNmtJ9Keg3f+/cqnywqLQgghOfelhKSXg=" options:NSDataBase64DecodingIgnoreUnknownCharacters];

// Check B size
if (bBytes.length == 0) {
    NSLog(@"Verifier SRP-6a safety check violated!");
    return;
}
[auth setSalt:salt];
[auth setB:bBytes];

// calculate session key & M
NSString *mBytes = [auth mBytesBase64];
NSString *sessionKey = [auth sessionKeyBase64];
if (auth.error) return;

// TODO: here we send M and receive R from server
NSData *rBytes = [NSData data];

// Check R size & validate it (can't test without server)
if (rBytes.length > 0 && [auth validateR:rBytes]) {
    NSLog(@"Succes autentification");
} else {
    NSLog(@"Invalide autentification");
}
```
