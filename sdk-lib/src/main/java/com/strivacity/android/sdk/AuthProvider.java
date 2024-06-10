package com.strivacity.android.sdk;

import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.util.Consumer;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import net.openid.appauth.AuthState;
import net.openid.appauth.AuthorizationRequest;
import net.openid.appauth.AuthorizationResponse;
import net.openid.appauth.AuthorizationService;
import net.openid.appauth.AuthorizationServiceConfiguration;
import net.openid.appauth.ClientAuthentication;
import net.openid.appauth.EndSessionRequest;
import net.openid.appauth.IdToken;
import net.openid.appauth.Preconditions;
import net.openid.appauth.ResponseTypeValues;
import net.openid.appauth.connectivity.ConnectionBuilder;
import net.openid.appauth.connectivity.DefaultConnectionBuilder;

import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class AuthProvider {

    private static final String TAG = "AuthProvider";

    private static final int REQUEST_CODE;
    private static final String[] DEFAULT_SCOPES;

    static {
        REQUEST_CODE = 0;
        DEFAULT_SCOPES = new String[] { "openid", "offline" };
    }

    static AuthProvider INSTANCE;

    private final ObjectMapper objectMapper;

    private final ConnectionBuilder defaultConnectionBuilder;
    private final AuthorizationService authService;
    final AuthStateManager authStateManager;

    private final Uri issuer;
    private final String clientId;
    private final Uri redirectUri;

    private String[] scopes;
    private String[] prompts;
    private String loginHint;
    private String acrValues;
    private String uiLocales;
    private Uri postLogoutUri;

    AuthActivityCallback authActivityCallback;
    EndSessionActivityCallback endSessionActivityCallback;

    private AuthProvider(
        Context context,
        Uri issuer,
        String clientId,
        Uri redirectUri,
        Storage storage
    ) {
        this.issuer = issuer;
        this.clientId = clientId;
        this.redirectUri = redirectUri;

        defaultConnectionBuilder = DefaultConnectionBuilder.INSTANCE;
        authStateManager = new AuthStateManager(storage);
        authService = new AuthorizationService(context);

        objectMapper = new ObjectMapper();
    }

    /**
     * <p>This method creates an {@link com.strivacity.android.sdk.AuthProvider} instance applying the given parameters.
     * You can implement your own storage logic using {@link com.strivacity.android.sdk.Storage} interface to
     * store the auth state more securely.</p>
     *
     * <p>Default scopes: <i>openid, offline</i>. You can define more scopes using {@link com.strivacity.android.sdk.AuthProvider#withScopes} function.</p>
     * <p>Please make sure you enabled refresh tokens in the client instance on admin console.</p>
     *
     * @throws NullPointerException if any field annotated with {@link androidx.annotation.NonNull} has null value
     *
     * @param context Application context
     * @param issuer The issuer URL
     * @param clientId Client ID of the client
     * @param redirectUri Redirect URI that is registered in the client
     * @param storage (Optional) Own implementation of a storage, where the auth state is stored
     * @return {@link com.strivacity.android.sdk.AuthProvider} instance
     */
    @NonNull
    @SuppressWarnings("unused")
    public static AuthProvider create(
        @NonNull Context context,
        @NonNull Uri issuer,
        @NonNull String clientId,
        @NonNull Uri redirectUri,
        @Nullable Storage storage
    ) {
        Preconditions.checkNotNull(context, "Context cannot be null");
        Preconditions.checkNotNull(issuer, "Issuer cannot be null");
        Preconditions.checkNotNull(clientId, "Client ID cannot be null");
        Preconditions.checkNotNull(redirectUri, "Redirect URI cannot be null");

        if (INSTANCE != null) {
            Log.w(
                TAG,
                "AuthProvider was created before, so the old config will be overridden"
            );
        }

        INSTANCE =
            new AuthProvider(
                context,
                issuer,
                clientId,
                redirectUri,
                storage == null ? new StorageImpl(context) : storage
            );

        return INSTANCE;
    }

    /**
     * <p>With this method, you can add scopes to the authorization request. If you don't provide any
     * scopes, default scopes are used. The scopes you provide are merged with the default scopes, so you
     * don't need to define those.</p>
     *
     * <p>Default scopes: <i>openid, offline</i>.</p>
     * <p>Please make sure you enabled refresh tokens in the client instance on admin console.</p>
     *
     * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims">Requesting Claims using Scope Values</a>
     *
     * @param scopes Scopes you want to send
     * @return {@link AuthProvider} instance
     */
    @NonNull
    @SuppressWarnings("unused")
    public AuthProvider withScopes(String... scopes) {
        this.scopes = scopes;
        return this;
    }

    /**
     * With this method, you can define the login hint.
     *
     * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint">OpenID Connect Authorization Endpoint section</a>
     *
     * @param loginHint Hint about the login identifier
     * @return {@link AuthProvider} instance
     */
    @NonNull
    @SuppressWarnings("unused")
    public AuthProvider withLoginHint(String loginHint) {
        this.loginHint = loginHint;
        return this;
    }

    /**
     * With this method, you can define the acr values.
     *
     * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint">OpenID Connect Authorization Endpoint section</a>
     *
     * @param acrValues Requested authentication context class reference values
     * @return {@link AuthProvider} instance
     */
    @NonNull
    @SuppressWarnings("unused")
    public AuthProvider withAcrValues(String acrValues) {
        this.acrValues = acrValues;
        return this;
    }

    /**
     * With this method, you can define the ui locales.
     *
     * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint">OpenID Connect Authorization Endpoint section</a>
     *
     * @param uiLocales End-user's preferred languages
     * @return {@link AuthProvider} instance
     */
    @NonNull
    @SuppressWarnings("unused")
    public AuthProvider withUiLocales(String uiLocales) {
        this.uiLocales = uiLocales;
        return this;
    }

    /**
     * With this method, you can add prompts.
     *
     * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint">OpenID Connect Authorization Endpoint section</a>
     *
     * @param prompts Prompts for reauthentication or consent of the End-User
     * @return {@link AuthProvider} instance
     */
    @NonNull
    @SuppressWarnings("unused")
    public AuthProvider withPrompts(String... prompts) {
        this.prompts = prompts;
        return this;
    }

    /**
     * With this method, you can define the redirection URL after logout.
     *
     * @see <a href="https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RedirectionAfterLogout">Redirection to RP After Logout</a>
     *
     * @param postLogoutUri Redirection URL after a logout
     * @return {@link AuthProvider} instance
     */
    @NonNull
    @SuppressWarnings("unused")
    public AuthProvider withPostLogoutUri(Uri postLogoutUri) {
        this.postLogoutUri = postLogoutUri;
        return this;
    }

    /**
     * <p>Using this method you can perform a PKCE Authorization Code flow with token exchange.
     * In the case of a successful login the {@link com.strivacity.android.sdk.FlowResponseCallback#success} method is called
     * returning the accessToken and claims. If there is any error, the {@link com.strivacity.android.sdk.FlowResponseCallback#failure}
     * method is called. If an authenticated state is found, then it returns the accessToken and claims without
     * opening the login page in a custom tab.</p>
     *
     * <p>Please make sure your client's "Token endpoint authentication method" is set to "None" on admin console!</p>
     *
     * @throws NullPointerException if any field annotated with {@link androidx.annotation.NonNull} has null value
     *
     * @param context Application context
     * @param callback {@link com.strivacity.android.sdk.FlowResponseCallback} instance that is called from this
     * method for return the accessToken and claims, or any error messages. Important: those functions sometimes are not
     * called from the main thread.
     */
    @SuppressWarnings("unused")
    public void startFlow(
        @NonNull Context context,
        @NonNull FlowResponseCallback callback
    ) {
        Preconditions.checkNotNull(context, "Context cannot be null");
        Preconditions.checkNotNull(callback, "Callback cannot be null");

        AuthorizationServiceConfiguration.fetchFromIssuer(
            issuer,
            (configuration, ex) -> {
                if (ex != null) {
                    Log.w(TAG, "error during getting configuration");
                    callback.failure(
                        AuthFlowException.of(
                            ex.error,
                            ex.errorDescription,
                            ex.getCause()
                        )
                    );
                    return;
                }

                if (configuration == null) {
                    Log.w(TAG, "configuration was not found");
                    callback.failure(AuthFlowException.UNEXPECTED);
                    return;
                }

                try {
                    if (
                        authStateManager
                            .getCurrentState()
                            .getAuthorizationServiceConfiguration() ==
                        null ||
                        !objectMapper
                            .readTree(
                                authStateManager
                                    .getCurrentState()
                                    .getAuthorizationServiceConfiguration()
                                    .toJsonString()
                            )
                            .equals(
                                objectMapper.readTree(
                                    configuration.toJsonString()
                                )
                            )
                    ) {
                        Log.i(TAG, "configuration changed");
                        authStateManager.setCurrentState(
                            new AuthState(configuration)
                        );
                    }
                } catch (JsonProcessingException ignored) {
                    Log.i(
                        TAG,
                        "error happened during checking configuration equality, fallback to the new configuration"
                    );
                    authStateManager.setCurrentState(
                        new AuthState(configuration)
                    );
                }

                checkAuthenticated(isAuthenticated -> {
                    if (isAuthenticated) {
                        Log.i(TAG, "state is authorized");

                        callback.success(
                            authStateManager.getCurrentState().getAccessToken(),
                            getLastRetrievedClaims()
                        );
                    } else {
                        int flags = 0;
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                            flags |= PendingIntent.FLAG_MUTABLE;
                        }

                        authActivityCallback =
                            new AuthActivityCallback() {
                                @Override
                                public void success(
                                    AuthorizationResponse response
                                ) {
                                    Log.i(
                                        TAG,
                                        "success callback, performing token request"
                                    );
                                    performTokenRequest(callback, response);
                                }

                                @Override
                                public void failure(
                                    AuthFlowException exception
                                ) {
                                    Log.i(TAG, "failure callback");
                                    callback.failure(exception);
                                }
                            };

                        Intent completeIntent = new Intent(
                            context,
                            AuthActivity.class
                        );
                        PendingIntent completePendingIntent = PendingIntent.getActivity(
                            context,
                            REQUEST_CODE,
                            completeIntent,
                            flags
                        );

                        AuthorizationRequest authorizationRequest = createAuthorizationRequest(
                            configuration
                        );

                        authService.performAuthorizationRequest(
                            authorizationRequest,
                            completePendingIntent,
                            completePendingIntent,
                            authService
                                .createCustomTabsIntentBuilder(
                                    authorizationRequest.toUri()
                                )
                                .build()
                        );
                    }
                });
            },
            defaultConnectionBuilder
        );
    }

    /**
     * Returns a valid accessToken if it is not expired, otherwise it tries to refresh it using the refresh token.
     * If there is any error, the {@link com.strivacity.android.sdk.FlowResponseCallback#failure}
     * method is called. Only the accessToken can have non null value in {@link com.strivacity.android.sdk.FlowResponseCallback#success}
     * parameters. Claims are also returned if those are presented.
     *
     * @throws NullPointerException if any field annotated with {@link androidx.annotation.NonNull} has null value
     *
     * @param callback {@link com.strivacity.android.sdk.FlowResponseCallback} instance that is called from this
     * method for return the accessToken and claims, or any error messages. Important: those functions sometimes are not
     * called from the main thread.
     */
    @SuppressWarnings("unused")
    public void getAccessToken(@NonNull FlowResponseCallback callback) {
        Preconditions.checkNotNull(callback, "Callback cannot be null");

        authStateManager
            .getCurrentState()
            .performActionWithFreshTokens(
                authService,
                (accessToken, idToken, ex) -> {
                    if (ex != null) {
                        callback.failure(
                            AuthFlowException.of(
                                ex.error,
                                ex.errorDescription,
                                ex.getCause()
                            )
                        );
                        return;
                    }

                    callback.success(accessToken, getLastRetrievedClaims());
                }
            );
    }

    /**
     * Returns claims from the last response of saved auth state.
     *
     * @return Claims if is presented otherwise null
     */
    @Nullable
    @SuppressWarnings("unused")
    public Map<String, Object> getLastRetrievedClaims() {
        IdToken parsedToken = authStateManager
            .getCurrentState()
            .getParsedIdToken();
        if (parsedToken == null) {
            return null;
        }
        return parsedToken.additionalClaims;
    }

    /**
     * This method tries to log out the authenticated account, and set the current state. If the state
     * has configuration, then only the configuration is saved in the storage, otherwise it
     * resets the current state to null and clear the storage. A custom tab appears with the logout
     * page of the Strivacity application if it successfully logged out the account. If the logout is
     * performed, then {@link com.strivacity.android.sdk.EndSessionCallback#finish} function called.
     *
     * @throws NullPointerException if any field annotated with {@link androidx.annotation.NonNull} has null value
     *
     * @param context Application context
     * @param callback {@link com.strivacity.android.sdk.EndSessionCallback} instance that is called
     * after logout performed. Important: that function sometimes is not called from the main thread.
     */
    @SuppressWarnings("unused")
    public void logout(
        @NonNull Context context,
        @NonNull EndSessionCallback callback
    ) {
        Preconditions.checkNotNull(context, "Context cannot be null");
        Preconditions.checkNotNull(callback, "Callback cannot be null");

        AuthorizationServiceConfiguration configuration = authStateManager
            .getCurrentState()
            .getAuthorizationServiceConfiguration();

        if (configuration == null) {
            authStateManager.resetCurrentState();
            callback.finish();
        } else {
            EndSessionRequest.Builder endSessionRequestBuilder = new EndSessionRequest.Builder(
                configuration
            )
                .setIdTokenHint(
                    authStateManager.getCurrentState().getIdToken()
                );

            if (postLogoutUri != null) {
                endSessionRequestBuilder.setPostLogoutRedirectUri(
                    postLogoutUri
                );
            }

            EndSessionRequest endSessionRequest = endSessionRequestBuilder.build();

            int flags = 0;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                flags |= PendingIntent.FLAG_MUTABLE;
            }

            endSessionActivityCallback = callback::finish;

            Intent endSessionIntent = new Intent(
                context,
                EndSessionActivity.class
            );

            authService.performEndSessionRequest(
                endSessionRequest,
                PendingIntent.getActivity(context, 0, endSessionIntent, flags),
                PendingIntent.getActivity(context, 0, endSessionIntent, flags)
            );

            authStateManager.setCurrentState(new AuthState(configuration));
        }
    }

    /**
     * With this method you can easily check if a state is authenticated or not. It also
     * tries to refresh the access token if needed. If the state is not authenticated or
     * it cannot refresh the access token, false returns, otherwise true.
     *
     * @throws NullPointerException if any field annotated with {@link androidx.annotation.NonNull} has null value
     *
     * @param authenticated This returns if the state is authenticated or not
     */
    @SuppressWarnings("unused")
    public void checkAuthenticated(@NonNull Consumer<Boolean> authenticated) {
        Preconditions.checkNotNull(authenticated, "Consumer cannot be null");

        if (
            authStateManager.getCurrentState().isAuthorized() &&
            !authStateManager.getCurrentState().getNeedsTokenRefresh()
        ) {
            Log.i(TAG, "authorized and don't need refresh token");
            authenticated.accept(true);
            return;
        }

        authStateManager
            .getCurrentState()
            .performActionWithFreshTokens(
                authService,
                (accessToken, idToken, ex) -> {
                    Log.i(TAG, "refresh token request");

                    if (accessToken == null || ex != null) {
                        Log.i(TAG, "not refreshed");
                        authenticated.accept(false);
                        return;
                    }

                    Log.i(TAG, "refreshed");
                    authenticated.accept(true);
                }
            );
    }

    private AuthorizationRequest createAuthorizationRequest(
        AuthorizationServiceConfiguration configuration
    ) {
        AuthorizationRequest.Builder requestBuilder = new AuthorizationRequest.Builder(
            configuration,
            clientId,
            ResponseTypeValues.CODE,
            redirectUri
        )
            .setScopes(
                Stream
                    .concat(
                        Arrays.stream(DEFAULT_SCOPES),
                        scopes == null ? Stream.empty() : Arrays.stream(scopes)
                    )
                    .collect(Collectors.toSet())
            );

        if (loginHint != null) {
            requestBuilder.setLoginHint(loginHint);
        }

        if (acrValues != null) {
            requestBuilder.setAdditionalParameters(
                Map.of("acr_values", acrValues)
            );
        }

        if (uiLocales != null) {
            requestBuilder.setUiLocales(this.uiLocales);
        }

        if (prompts != null) {
            requestBuilder.setPromptValues(prompts);
        }

        return requestBuilder.build();
    }

    private void performTokenRequest(
        FlowResponseCallback callback,
        AuthorizationResponse response
    ) {
        try {
            if (response == null) {
                callback.failure(AuthFlowException.UNEXPECTED);
                return;
            }

            authService.performTokenRequest(
                response.createTokenExchangeRequest(),
                authStateManager.getCurrentState().getClientAuthentication(),
                (tokenResponse, exception) -> {
                    authStateManager.updateCurrentState(
                        tokenResponse,
                        exception
                    );

                    if (tokenResponse != null) {
                        callback.success(
                            tokenResponse.accessToken,
                            getLastRetrievedClaims()
                        );
                    } else {
                        if (exception != null) {
                            callback.failure(
                                AuthFlowException.of(
                                    exception.error,
                                    exception.errorDescription,
                                    exception.getCause()
                                )
                            );
                        } else {
                            callback.failure(AuthFlowException.UNEXPECTED);
                        }
                    }
                }
            );
        } catch (ClientAuthentication.UnsupportedAuthenticationMethod ex) {
            callback.failure(
                AuthFlowException.unsupportedAuthenticationMethod(
                    ex.getUnsupportedAuthenticationMethod(),
                    ex.getCause()
                )
            );
        }
    }

    interface AuthActivityCallback {
        void success(AuthorizationResponse response);
        void failure(AuthFlowException exception);
    }

    interface EndSessionActivityCallback {
        void finished();
    }
}
