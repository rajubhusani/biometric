#import <LocalAuthentication/LocalAuthentication.h>
#import "BiometricPlugin.h"

@interface BiometricPlugin ()
@property(copy, nullable) NSDictionary<NSString *, NSNumber *> *lastCallArgs;
@property(nullable) FlutterResult lastResult;
@end

@implementation BiometricPlugin

+ (void)registerWithRegistrar:(NSObject<FlutterPluginRegistrar> *)registrar {
    FlutterMethodChannel *channel =
    [FlutterMethodChannel methodChannelWithName:@"biometric"
                                binaryMessenger:[registrar messenger]];
    BiometricPlugin *instance = [[BiometricPlugin alloc] init];
    [registrar addMethodCallDelegate:instance channel:channel];
    [registrar addApplicationDelegate:instance];
}

- (void)handleMethodCall:(FlutterMethodCall *)call result:(FlutterResult)result {
    
    if ([@"authenticate" isEqualToString:call.method]) {
        bool isBiometricOnly = [call.arguments[@"biometricOnly"] boolValue];
        if (isBiometricOnly) {
            [self authenticateWithBiometrics:call.arguments withFlutterResult:result];
        } else {
            [self authenticate:call.arguments withFlutterResult:result];
        }
    } else if ([@"getAvailableBiometrics" isEqualToString:call.method]) {
        [self getAvailableBiometrics:result];
    } else if ([@"isDeviceSupported" isEqualToString:call.method]) {
        result(@YES);
    } else {
        result(FlutterMethodNotImplemented);
    }
}

#pragma mark Private Methods

- (void)alertMessage:(NSString *)message
         firstButton:(NSString *)firstButton
       flutterResult:(FlutterResult)result
    additionalButton:(NSString *)secondButton {
    UIAlertController *alert =
    [UIAlertController alertControllerWithTitle:@""
                                        message:message
                                 preferredStyle:UIAlertControllerStyleAlert];
    
    UIAlertAction *defaultAction = [UIAlertAction actionWithTitle:firstButton
                                                            style:UIAlertActionStyleDefault
                                                          handler:^(UIAlertAction *action) {
        result(@NO);
    }];
    
    [alert addAction:defaultAction];
    if (secondButton != nil) {
        UIAlertAction *additionalAction = [UIAlertAction
                                           actionWithTitle:secondButton
                                           style:UIAlertActionStyleDefault
                                           handler:^(UIAlertAction *action) {
            if (UIApplicationOpenSettingsURLString != NULL) {
                NSURL *url = [NSURL URLWithString:UIApplicationOpenSettingsURLString];
                [[UIApplication sharedApplication] openURL:url];
                result(@NO);
            }
        }];
        [alert addAction:additionalAction];
    }
    [[UIApplication sharedApplication].delegate.window.rootViewController presentViewController:alert
                                                                                       animated:YES
                                                                                     completion:nil];
}

- (void)getAvailableBiometrics:(FlutterResult)result {
    LAContext *context = [[LAContext alloc] init];
    NSError *authError = nil;
    NSMutableArray<NSString *> *biometrics = [[NSMutableArray<NSString *> alloc] init];
    if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                             error:&authError]) {
        if (authError == nil) {
            if (@available(iOS 11.0.1, *)) {
                if (context.biometryType == LABiometryTypeFaceID) {
                    [biometrics addObject:@"face"];
                } else if (context.biometryType == LABiometryTypeTouchID) {
                    [biometrics addObject:@"fingerprint"];
                }
            } else {
                [biometrics addObject:@"fingerprint"];
            }
        }
    } else if (authError.code == LAErrorTouchIDNotEnrolled) {
        [biometrics addObject:@"undefined"];
    }
    result(biometrics);
}
- (void)authenticateWithBiometrics:(NSDictionary *)arguments
                 withFlutterResult:(FlutterResult)result {
    LAContext *context = [[LAContext alloc] init];
    NSError *authError = nil;
    self.lastCallArgs = nil;
    self.lastResult = nil;
    context.localizedFallbackTitle = @"";
    
    if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                             error:&authError]) {
        [context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                localizedReason:arguments[@"localizedReason"]
                          reply:^(BOOL success, NSError *error) {
            if (success) {
                result(@YES);
            } else {
                switch (error.code) {
                    case LAErrorPasscodeNotSet:
                    case LAErrorTouchIDNotAvailable:
                    case LAErrorTouchIDNotEnrolled:
                    case LAErrorTouchIDLockout:
                        [self handleErrors:error
                          flutterArguments:arguments
                         withFlutterResult:result];
                        return;
                    case LAErrorSystemCancel:
                        if ([arguments[@"stickyAuth"] boolValue]) {
                            self.lastCallArgs = arguments;
                            self.lastResult = result;
                            return;
                        }
                }
                result(@NO);
            }
        }];
    } else {
        [self handleErrors:authError flutterArguments:arguments withFlutterResult:result];
    }
}

- (void)authenticate:(NSDictionary *)arguments withFlutterResult:(FlutterResult)result {
    LAContext *context = [[LAContext alloc] init];
    NSError *authError = nil;
    _lastCallArgs = nil;
    _lastResult = nil;
    context.localizedFallbackTitle = @"";
    
    if (@available(iOS 9.0, *)) {
        if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&authError]) {
            [context evaluatePolicy:kLAPolicyDeviceOwnerAuthentication
                    localizedReason:arguments[@"localizedReason"]
                              reply:^(BOOL success, NSError *error) {
                if (success) {
                    result(@YES);
                } else {
                    switch (error.code) {
                        case LAErrorPasscodeNotSet:
                        case LAErrorTouchIDNotAvailable:
                        case LAErrorTouchIDNotEnrolled:
                        case LAErrorTouchIDLockout:
                            [self handleErrors:error
                              flutterArguments:arguments
                             withFlutterResult:result];
                            return;
                        case LAErrorSystemCancel:
                            if ([arguments[@"stickyAuth"] boolValue]) {
                                self->_lastCallArgs = arguments;
                                self->_lastResult = result;
                                return;
                            }
                    }
                    result(@NO);
                }
            }];
        } else {
            [self handleErrors:authError flutterArguments:arguments withFlutterResult:result];
        }
    } else {
        // Fallback on earlier versions
    }
}

- (void)handleErrors:(NSError *)authError
    flutterArguments:(NSDictionary *)arguments
   withFlutterResult:(FlutterResult)result {
    NSString *errorCode = @"NotAvailable";
    switch (authError.code) {
        case LAErrorPasscodeNotSet:
        case LAErrorTouchIDNotEnrolled:
            if ([arguments[@"useErrorDialogs"] boolValue]) {
                [self alertMessage:arguments[@"goToSettingDescriptionIOS"]
                       firstButton:arguments[@"okButton"]
                     flutterResult:result
                  additionalButton:arguments[@"goToSetting"]];
                return;
            }
            errorCode = authError.code == LAErrorPasscodeNotSet ? @"PasscodeNotSet" : @"NotEnrolled";
            break;
        case LAErrorTouchIDLockout:
            [self alertMessage:arguments[@"lockOut"]
                   firstButton:arguments[@"okButton"]
                 flutterResult:result
              additionalButton:nil];
            return;
    }
    result([FlutterError errorWithCode:errorCode
                               message:authError.localizedDescription
                               details:authError.domain]);
}

#pragma mark - AppDelegate

- (void)applicationDidBecomeActive:(UIApplication *)application {
    if (self.lastCallArgs != nil && self.lastResult != nil) {
        [self authenticateWithBiometrics:_lastCallArgs withFlutterResult:self.lastResult];
    }
}

@end
