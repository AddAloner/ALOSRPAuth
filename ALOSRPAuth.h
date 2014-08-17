//
//  ALOSRPAuth.h
//
//  Created by Alexey Yachmenev on 13.08.14.
//  Copyright (c) 2014 e-Legion. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "srp.h"

typedef NS_ENUM(NSUInteger, ALOSRPHashAlgorithm)
{
    ALOSRPSHA1 = SRP_SHA1,
    ALOSRPSHA224 = SRP_SHA224,
    ALOSRPSHA256 = SRP_SHA256,
    ALOSRPSHA384 = SRP_SHA384,
    ALOSRPSHA512 = SRP_SHA512
};

@interface ALOSRPPrivateData : NSObject

@property (nonatomic, copy) NSString *vNHex;
@property (nonatomic, copy) NSString *vgHex;

- (instancetype)initWithN:(NSString *)NHex g:(NSString *)gHex;
+ (instancetype)privateDataWithN:(NSString *)NHex g:(NSString *)gHex;

@end

@interface ALOSRPAuth : NSObject

@property (nonatomic, assign) NSStringEncoding encoding;
@property (nonatomic, assign) ALOSRPHashAlgorithm hashAlgorithm;
@property (nonatomic, strong) ALOSRPPrivateData *privateData;
@property (readonly) NSData *sessionKey;
@property (readonly) NSData *aBytes;
@property (readonly) NSData *mBytes;
@property (readonly) NSError *error;

- (instancetype)initWithPrivateData:(ALOSRPPrivateData*)privateData;
- (instancetype)initWithN:(NSString*)NHex g:(NSString*)gHex;
- (instancetype)initWithPrivateData:(ALOSRPPrivateData*)privateData login:(NSString*)login password:(NSString*)password;
- (instancetype)initWithN:(NSString*)NHex g:(NSString*)gHex login:(NSString*)login password:(NSString*)password;
- (instancetype)initWithPrivateData:(ALOSRPPrivateData*)privateData login:(NSString*)login password:(NSString*)password salt:(NSData*)salt bBytes:(NSData*)bBytes;
- (instancetype)initWithN:(NSString*)NHex g:(NSString*)gHex login:(NSString*)login password:(NSString*)password salt:(NSData*)salt bBytes:(NSData*)bBytes;

- (void)setB:(NSData*)bBytes;
- (void)setSalt:(NSData*)salt;
- (void)setLogin:(NSString*)login;
- (void)setPassword:(NSString*)password;

- (NSString*)aBytesBase64;
- (NSString*)mBytesBase64;
- (NSString*)sessionKeyBase64;

- (BOOL)startAuthorization;
- (void)resetAuthorization;

- (BOOL)validateR:(NSData*)rBytes;

@end
