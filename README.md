![Strivacity Android SDK](https://static.strivacity.com/images/android-native-sdk-banner.png)

[![Maven Central](https://img.shields.io/maven-central/v/com.strivacity.android/sdk)](https://search.maven.org/artifact/com.strivacity.android/sdk) \| [View in Documentation](https://docs.strivacity.com/docs/android-mobile-sdk)

See our [Developer Portal](https://www.strivacity.com/learn-support/developer-hub) to get started with developing for the Strivacity product.

# Overview

This SDK allows you to integrate Strivacity’s policy-driven journeys into your brand’s Android mobile application. It implements Strivacity's no-code components via [Android Custom Tabs](https://developer.chrome.com/docs/android/custom-tabs).

This SDK uses <https://appauth.io>, which follows the best practices from [RFC 8252 - OAuth 2.0 for Native Apps](https://tools.ietf.org/html/rfc8252),  including using in-app browser views like Android Custom Tabs. Embedded user-agents, known as web-views, are not supported due to usability and security reasons documented in [Section 8.12 of RFC 8252](https://tools.ietf.org/html/rfc8252#section-8.12).

The SDK uses the [PKCE extension to OAuth](https://tools.ietf.org/html/rfc7636) to ensure the secure exchange of authorization codes in public clients.

## Download

Strivacity SDK for Android is available on [MavenCentral](https://search.maven.org/search?q=g:com.strivacity.android%20AND%20a:sdk).

```groovy
implementation 'com.strivacity.android:sdk:<version>'
```

## Demo App

A demo app is part of this repository. To run the demo app, first, you need to configure  
credentials.properties file which can be found under app folder (after you build app's gradle).

## Overview

Note: The internal implementation of the Strivacity SDK for Android relies on the open source [AppAuth Library](https://github.com/openid/AppAuth-Android).

Strivacity SDK for Android provides the possibility to build an application which can communicate with Strivacity using OAuth 2.0 PKCE flow.  
You can define your own storage logic using the [Storage](https://github.com/Strivacity/sdk-mobile-android/blob/main/sdk-lib/src/main/java/com/strivacity/android/sdk/Storage.java) interface.  
Refresh token can be used to refresh the auth state instead of running authentication again.

## Before you use the SDK

You have to define your applicationId in the gradle file of your app:

```groovy
android {
  defaultConfig {
    manifestPlaceholders = [
      'appAuthRedirectScheme': '<your applicationId>'
    ]
  }
}
```

[Read more about applicationId](https://developer.android.com/build/configure-app-module).

## Initialize AuthProvider

First, you must call the AuthProvider create method to create an instance:

```text
AuthProvider provider = AuthProvider.create(
    context,
    issuer,                                      // specifies authentication server domain
    clientId,                                    // specifies OAuth client ID
    redirectUri,                                 // specifies the redirect uri
    storage                                      // optional, you can provide the storage logic you implemented using Storage interface, or use the default unsecure storage logic
);
```

### Define more configurations

After you created the provider instance you can add more configs to fit your flow.

```text
provider
    .withScopes()                       // for defining scopes (openid, offline is included by default)
    .withLoginHint()                    // for defining login hint
    .withAcrValues()                    // for defining acr values
    .withUiLocales()                    // for defining ui locales
    .withPrompts()                      // for defining prompts
    .withPostLogoutUri()                // for defining redirect uri after logout
```

## Starting the flow

After a successful set up, you can use the startFlow method to initiate the login process.  
You have to provide the context, and define a callback which is called from this method.

```text
FlowResponseCallback callback = new FlowResponseCallback() {
    @Override
    public void success(
        @Nullable String accessToken,
        @Nullable Map<String, Object> claims
    ) {
        // add success logic here
    }
    
    @Override
    public void failure(@NonNull AuthFlowException exception) {
        // handle error
    }
}
Map<String, String> additionalRefreshTokenParameters = Map.of("key", "value");
provider.startFlow(context, callback, additionalRefreshTokenParameters);
```

## Get access token

To obtain the access token you can use getAccessToken method to retrieve it from the auth state  
or the method tries to refresh it using refresh token. Claims also return besides the access token.  
You can take the same callback here like in startFlow.

```text
FlowResponseCallback callback = new FlowResponseCallback() {
    @Override
    public void success(
        @Nullable String accessToken,
        @Nullable Map<String, Object> claims
    ) {
        // add success logic here
    }
    
    @Override
    public void failure(@NonNull AuthFlowException exception) {
        // handle error
    }
}
Map<String, String> additionalRefreshTokenParameters = Map.of("key", "value");
provider.getAccessToken(callback, additionalRefreshTokenParameters);
```

## Get claims

You have the possibility to get the claims from the last id token response (if it exists).  
For this, call the getLastRetrievedClaims method which accept a Consumer that have a Map argument that contains the claims.  
If there wasn't any claim, null returns.

```text
provider.getLastRetrievedClaims((claims) -> {
    // process claims
});
```

## Get last token additional parameters

If you are using token refreshing to renew your access token, you have the possibility to create a token refresh hook in the Admin Console
and pass additional information from the hook back to the mobile next to the new tokens. To do this, just use the following code.
```text
provider.getLastTokenResponseAdditionalParameters((additionalParameters) -> {
    // process additional parameters
});
```

## Perform logout

After the logout, callback function is called both on success or failure logout. If there was no  
auth state then it is removed from the storage.

```text
EndSessionCallback callback = new EndSessionCallback() {
    @Override
    public void finish() {
        // add some logic here
    }
}
provider.logout(context, callback);
```

## Checking authState is authenticated

There is a method where you can check if the auth state stored in the storage is authenticated or not.

```text
Map<String, String> additionalRefreshTokenParameters = Map.of("key", "value");
provider.checkAuthenticated(isAuthenticated -> {
    // add some logic here
}, additionalRefreshTokenParameters);
```
## Building
To build using gradle, there are a number of required dependencies:
- openjdk-17-jdk
- android-sdk
  - Be sure to set the `ANDROID_HOME` environment variable
- [Android Command-line tools](https://developer.android.com/studio#command-line-tools-only)
  - Be sure to install at the correct location so binaries are located at `$ANDROID_HOME/cmdline-tools/<VERSION>/bin/`
  - Please note, the command-line tools include the `sdkmanager` binary, which is used during the build.  Before building, you must accept the sdkmanager licenses by invoking `sdkmanager --licenses`.
- npm


## Publishing

To publish this packages to Maven Central, you'll need to do the following:
 - Ensure your `~/.gradle/gradle.properties` has the following values set:
   - `signing.keyId` - 8-digit short key id. `gpg -K --keyid-format short` will display it
   - `signing.password` - password of key
   - `signing.secretKeyRingFile` - gpg keyring containing secret key
     - run `gpg --export-secret-keys -o your-keyring.gpg` to create the file
 - Set `OSSRH_USERNAME` and `OSSRH_PASSWORD` environment variables containing sonatype nexus tokens
   - Login to https://s01.oss.sonatype.org/, and use the User Token from your profile for these values
 - Invoke the following command, with the appropriate version:
```shell
./gradlew -Pversion=2.1.0 -d publish
```
After successful publish, you will have to follow [these instructions](https://central.sonatype.org/publish/release/) to "Close" and "Drop" or "Release" your staging repository.  Once released, it will be sync'd to Maven central and should show up within a few minutes.

## Author

Strivacity: [opensource@strivacity.com](mailto:opensource@strivacity.com)

## License

Strivacity is available under the Apache License, Version 2.0. See the [LICENSE](./LICENSE) file for more info.

## Vulnerability Reporting

The [Guidelines for responsible disclosure](https://www.strivacity.com/report-a-security-issue) details the procedure for disclosing security issues.  
Please do not report security vulnerabilities on the public issue tracker.
