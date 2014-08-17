//
//  RFSRP.m
//  RFCorp
//
//  Created by Alexey Yachmenev on 13.08.14.
//  Copyright (c) 2014 e-Legion. All rights reserved.
//

#import "ALOSRPAuth.h"

static NSStringEncoding const kRequestEncoding = NSUTF8StringEncoding;
static NSString* const kSRPErrorDomain = @"ALOSRP";
static NSInteger const kInitError = 10;
static NSInteger const kCalculateError = 11;

@implementation ALOSRPPrivateData

- (instancetype)initWithN:(NSString *)NHex g:(NSString *)gHex
{
    if (self = [super init]) {
        _vNHex = NHex;
        _vgHex = gHex;
    }
    return self;
}

+ (instancetype)privateDataWithN:(NSString *)NHex g:(NSString *)gHex
{
    return [[self alloc] initWithN:NHex g:gHex];
}

@end

@interface ALOSRPAuth ()

@property (nonatomic, assign) struct SRPUser *usr;
@property (nonatomic, copy) NSString *login;
@property (nonatomic, copy) NSString *password;
@property (nonatomic, copy, setter = setB:) NSData *bBytes;
@property (nonatomic, copy) NSData *salt;

@end;

@implementation ALOSRPAuth

@synthesize aBytes = _aBytes;
@synthesize mBytes = _mBytes;
@synthesize sessionKey = _sessionKey;

#pragma mark - Init

- (id)init
{
    if (self  = [super init]) {
        _encoding = kRequestEncoding;
        _hashAlgorithm = ALOSRPSHA256;
    }
    return self;
}

- (instancetype)initWithPrivateData:(ALOSRPPrivateData *)privateData
{
    if (self = [self init]) {
        _privateData = privateData;
    }
    return self;
}

- (instancetype)initWithN:(NSString *)NHex g:(NSString *)gHex
{
    if (self = [self init]) {
        _privateData = [ALOSRPPrivateData privateDataWithN:NHex g:gHex];
    }
    return self;
}

- (instancetype)initWithPrivateData:(ALOSRPPrivateData *)privateData login:(NSString *)login password:(NSString *)password
{
    if (self = [self initWithPrivateData:privateData]) {
        _login = login;
        _password = password;
    }
    return self;
}

- (instancetype)initWithN:(NSString *)NHex g:(NSString *)gHex login:(NSString *)login password:(NSString *)password
{
    if (self = [self initWithN:NHex g:gHex]) {
        _login = login;
        _password = password;
    }
    return self;
}

- (instancetype)initWithN:(NSString *)NHex g:(NSString *)gHex login:(NSString *)login password:(NSString *)password salt:(NSData *)salt bBytes:(NSData *)bBytes
{
    if (self = [self initWithN:NHex g:gHex login:login password:password]) {
        _salt = salt;
        _bBytes = bBytes;
    }
    return self;
}

- (instancetype)initWithPrivateData:(ALOSRPPrivateData *)privateData login:(NSString *)login password:(NSString *)password salt:(NSData *)salt bBytes:(NSData *)bBytes
{
    if (self = [self initWithPrivateData:privateData login:login password:password]) {
        _salt = salt;
        _bBytes = bBytes;
    }
    return self;
}

#pragma mark - Properties

- (NSData *)aBytes
{
    if (_aBytes == nil) [self calculateA];
    return _aBytes;
}

- (NSData *)sessionKey
{
    if (_sessionKey == nil) [self calculateSessionKeyAndM];
    return _sessionKey;
}

- (NSData *)mBytes
{
    if (_mBytes == nil) [self calculateSessionKeyAndM];
    return _mBytes;
}

#pragma mark Keys in Base64

- (NSString*)sessionKeyBase64
{
    return [self.sessionKey base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
}

- (NSString*)aBytesBase64
{
    return [self.aBytes base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
}

- (NSString*)mBytesBase64
{
    return [self.mBytes base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
}

#pragma mark - Logic

- (BOOL)startAuthorization
{
    if (self.login && self.password && self.privateData) {
        const char * usernameChar = [self.login cStringUsingEncoding:self.encoding];
        const char * passwordChar = [self.password cStringUsingEncoding:self.encoding];
        
        const char * n_hex = [self.privateData.vNHex cStringUsingEncoding:self.encoding];
        const char * g_hex = [self.privateData.vgHex cStringUsingEncoding:self.encoding];
        
        SRP_HashAlgorithm alg = (SRP_HashAlgorithm)self.hashAlgorithm;
        SRP_NGType ng_type = SRP_NG_CUSTOM;
        
        _usr = srp_user_new(alg, ng_type, usernameChar, (unsigned char*)passwordChar, (unsigned int)strlen(passwordChar), n_hex, g_hex);
        return YES;
    }
    NSString *localizedDescription;
    if (self.login == nil) {
        localizedDescription = @"Need `login` for initialize SRP authorizaion";
    } else if (self.password == nil) {
        localizedDescription = @"Need `password` for initialize SRP authorizaion";
    } else {
        localizedDescription = @"Need private data (N&g) for initialize SRP authorizaion";
    }
    _error = [NSError errorWithDomain:kSRPErrorDomain code:kInitError userInfo:@{NSLocalizedDescriptionKey: localizedDescription}];
    return NO;
}

- (void)resetAuthorization
{
    _usr = nil;
    _aBytes = nil;
    _mBytes = nil;
    _error = nil;
}

- (void)calculateA
{
    if (self.usr) {
        const char *username;
        const unsigned char * bytesA = 0;
        int lenA = 0;
        srp_user_start_authentication(self.usr, &username, &bytesA, &lenA);
        _aBytes = [NSData dataWithBytes:bytesA length:lenA];
        return;
    }
    _error = [NSError errorWithDomain:kSRPErrorDomain code:kCalculateError userInfo:@{NSLocalizedDescriptionKey: @"Uninitializing SRP info"}];
}

- (void)calculateSessionKeyAndM
{
    if (self.usr && self.aBytes && self.bBytes && self.salt)
    {
        const unsigned char * bytesSalt = [self.salt bytes];
        const unsigned char * bytesB = [self.bBytes bytes];
        const unsigned char * bytesM = 0;
        const unsigned char * sessionKey;
        
        int lenSalt = (int)self.salt.length;
        int lenB = (int)self.bBytes.length;
        int lenM = 0;
        int len_SessionKey = 0;
        
        srp_user_process_challenge(self.usr, (unsigned char*)bytesSalt, lenSalt, (unsigned char*)bytesB, lenB, &bytesM, &lenM);
        sessionKey = srp_user_get_session_key(self.usr, &len_SessionKey);
        
        _sessionKey = [NSData dataWithBytes:sessionKey length:len_SessionKey];
        _mBytes = [NSData dataWithBytes:bytesM length:lenM];
        return;
    }
    NSString *localizedDescription;
    if (self.salt == nil) {
        localizedDescription = @"Need `salt` for calculate session key & M";
    } else if (self.bBytes == nil) {
        localizedDescription = @"Need B for calculate session key & M";
    } else {
        localizedDescription = @"Uninitializing SRP info";
    }
    _error = [NSError errorWithDomain:kSRPErrorDomain code:kCalculateError userInfo:@{NSLocalizedDescriptionKey: localizedDescription}];
}

- (BOOL)validateR:(NSData*)rBytes
{
    const unsigned char * bytesR = [rBytes bytes];
    srp_user_verify_session(self.usr, bytesR);
    return srp_user_is_authenticated(self.usr);
}

@end