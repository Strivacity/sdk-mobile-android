package com.strivacity.android.sdk;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

import android.content.Context;
import android.net.Uri;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import net.openid.appauth.AuthState;
import net.openid.appauth.AuthorizationException;
import net.openid.appauth.AuthorizationRequest;
import net.openid.appauth.AuthorizationResponse;
import net.openid.appauth.AuthorizationServiceConfiguration;
import net.openid.appauth.TokenRequest;
import net.openid.appauth.TokenResponse;

@RunWith(AndroidJUnit4.class)
public class AuthStateManagerIT {

    private static final String AUTH_ENDPOINT = "http://example.com/auth";
    private static final String TOKEN_ENDPOINT = "http://example.com/token";

    private AuthStateManager authStateManager;
    private Storage storage;

    @Before
    public void setUp() {
        Context context = InstrumentationRegistry
            .getInstrumentation()
            .getTargetContext();

        storage = new StorageImpl(context);
        AuthorizationServiceConfiguration configuration = new AuthorizationServiceConfiguration(
            Uri.parse(AUTH_ENDPOINT),
            Uri.parse(TOKEN_ENDPOINT)
        );
        storage.setState(new AuthState(configuration));

        authStateManager = new AuthStateManager(storage);
    }

    @Test
    public void getCurrentStateFromStorage() {
        AuthState state = authStateManager.getCurrentState();
        assertAuthStateConfigUrls(state, AUTH_ENDPOINT, TOKEN_ENDPOINT);
    }

    @Test
    public void getCurrentStateFromStorageButItIsEmpty() {
        storage.setState(null);
        AuthState state = authStateManager.getCurrentState();
        assertThat(
            state.getAuthorizationServiceConfiguration(),
            is(nullValue())
        );
    }

    @Test
    public void getCurrentState() {
        AuthState state = authStateManager.getCurrentState();
        assertAuthStateConfigUrls(state, AUTH_ENDPOINT, TOKEN_ENDPOINT);
        storage.setState(new AuthState());
        state = authStateManager.getCurrentState();
        assertAuthStateConfigUrls(state, AUTH_ENDPOINT, TOKEN_ENDPOINT);
    }

    @Test
    public void setCurrentState() {
        String newAuthUri = "http://new-domain/auth";
        String newTokenUri = "http://new-domain/token";

        AuthorizationServiceConfiguration configuration = new AuthorizationServiceConfiguration(
            Uri.parse(newAuthUri),
            Uri.parse(newTokenUri)
        );
        AuthState state = new AuthState(configuration);

        authStateManager.setCurrentState(state);

        assertAuthStateConfigUrls(
            authStateManager.getCurrentState(),
            newAuthUri,
            newTokenUri
        );
        assertAuthStateConfigUrls(storage.getState(), newAuthUri, newTokenUri);
    }

    @Test
    public void updateCurrentStateAuthResponse() {
        AuthorizationRequest request = new AuthorizationRequest.Builder(
            new AuthorizationServiceConfiguration(
                Uri.parse(AUTH_ENDPOINT),
                Uri.parse(TOKEN_ENDPOINT)
            ),
            "client_id",
            "code",
            Uri.parse("http://redirect-uri/callback")
        )
            .build();

        AuthorizationResponse response = new AuthorizationResponse.Builder(
            request
        )
            .setAccessToken("access_token")
            .setIdToken("id_token")
            .build();

        authStateManager.updateCurrentState(response, null);

        AuthState stateFromCurrentState = authStateManager.getCurrentState();
        assertAuthStateConfigUrls(
            stateFromCurrentState,
            AUTH_ENDPOINT,
            TOKEN_ENDPOINT
        );
        assertThat(
            stateFromCurrentState.getAccessToken(),
            equalTo("access_token")
        );
        assertThat(stateFromCurrentState.getIdToken(), equalTo("id_token"));

        AuthState stateFromStorage = storage.getState();
        assertAuthStateConfigUrls(
            stateFromStorage,
            AUTH_ENDPOINT,
            TOKEN_ENDPOINT
        );
        assertThat(stateFromStorage.getAccessToken(), equalTo("access_token"));
        assertThat(stateFromStorage.getIdToken(), equalTo("id_token"));
    }

    @Test
    public void updateCurrentStateAuthResponseException() {
        int exceptionType =
            AuthorizationException.TYPE_OAUTH_AUTHORIZATION_ERROR;
        AuthorizationException exception = new AuthorizationException(
            exceptionType,
            1000,
            "error",
            "error_description",
            null,
            null
        );

        authStateManager.updateCurrentState(
            (AuthorizationResponse) null,
            exception
        );

        AuthState stateFromCurrentState = authStateManager.getCurrentState();
        assertAuthStateConfigUrls(
            stateFromCurrentState,
            AUTH_ENDPOINT,
            TOKEN_ENDPOINT
        );
        assertThat(
            stateFromCurrentState.getAuthorizationException(),
            is(notNullValue())
        );
        assertThat(
            stateFromCurrentState.getAuthorizationException().error,
            equalTo("error")
        );
        assertThat(
            stateFromCurrentState.getAuthorizationException().errorDescription,
            equalTo("error_description")
        );
        assertThat(
            stateFromCurrentState.getAuthorizationException().code,
            equalTo(1000)
        );

        AuthState stateFromStorage = storage.getState();
        assertAuthStateConfigUrls(
            stateFromStorage,
            AUTH_ENDPOINT,
            TOKEN_ENDPOINT
        );
        assertThat(
            stateFromStorage.getAuthorizationException(),
            is(notNullValue())
        );
        assertThat(
            stateFromStorage.getAuthorizationException().error,
            equalTo("error")
        );
        assertThat(
            stateFromCurrentState.getAuthorizationException().errorDescription,
            equalTo("error_description")
        );
        assertThat(
            stateFromStorage.getAuthorizationException().code,
            equalTo(1000)
        );
    }

    @Test
    public void updateCurrentStateTokenResponse() {
        TokenRequest request = new TokenRequest.Builder(
            new AuthorizationServiceConfiguration(
                Uri.parse(AUTH_ENDPOINT),
                Uri.parse(TOKEN_ENDPOINT)
            ),
            "client_id"
        )
            .setGrantType("code")
            .build();

        TokenResponse response = new TokenResponse.Builder(request)
            .setAccessToken("access_token")
            .setIdToken("id_token")
            .build();

        authStateManager.updateCurrentState(response, null);

        AuthState stateFromCurrentState = authStateManager.getCurrentState();
        assertAuthStateConfigUrls(
            stateFromCurrentState,
            AUTH_ENDPOINT,
            TOKEN_ENDPOINT
        );
        assertThat(
            stateFromCurrentState.getAccessToken(),
            equalTo("access_token")
        );
        assertThat(stateFromCurrentState.getIdToken(), equalTo("id_token"));

        AuthState stateFromStorage = storage.getState();
        assertAuthStateConfigUrls(
            stateFromStorage,
            AUTH_ENDPOINT,
            TOKEN_ENDPOINT
        );
        assertThat(stateFromStorage.getAccessToken(), equalTo("access_token"));
        assertThat(stateFromStorage.getIdToken(), equalTo("id_token"));
    }

    @Test
    public void updateCurrentStateTokenResponseException() {
        int exceptionType = AuthorizationException.TYPE_OAUTH_TOKEN_ERROR;
        AuthorizationException exception = new AuthorizationException(
            exceptionType,
            1000,
            "error",
            "error_description",
            null,
            null
        );

        authStateManager.updateCurrentState((TokenResponse) null, exception);

        AuthState stateFromCurrentState = authStateManager.getCurrentState();
        assertAuthStateConfigUrls(
            stateFromCurrentState,
            AUTH_ENDPOINT,
            TOKEN_ENDPOINT
        );
        assertThat(
            stateFromCurrentState.getAuthorizationException(),
            is(notNullValue())
        );
        assertThat(
            stateFromCurrentState.getAuthorizationException().error,
            equalTo("error")
        );
        assertThat(
            stateFromCurrentState.getAuthorizationException().errorDescription,
            equalTo("error_description")
        );
        assertThat(
            stateFromCurrentState.getAuthorizationException().code,
            equalTo(1000)
        );

        AuthState stateFromStorage = storage.getState();
        assertAuthStateConfigUrls(
            stateFromStorage,
            AUTH_ENDPOINT,
            TOKEN_ENDPOINT
        );
        assertThat(
            stateFromStorage.getAuthorizationException(),
            is(notNullValue())
        );
        assertThat(
            stateFromCurrentState.getAuthorizationException().error,
            equalTo("error")
        );
        assertThat(
            stateFromCurrentState.getAuthorizationException().errorDescription,
            equalTo("error_description")
        );
        assertThat(
            stateFromCurrentState.getAuthorizationException().code,
            equalTo(1000)
        );
    }

    @Test
    public void resetCurrentState() {
        authStateManager.resetCurrentState();

        assertThat(storage.getState(), is(nullValue()));
        assertThat(
            authStateManager
                .getCurrentState()
                .getAuthorizationServiceConfiguration(),
            is(nullValue())
        );
    }

    private void assertAuthStateConfigUrls(
        AuthState state,
        String authUri,
        String tokenUri
    ) {
        assertThat(
            state.getAuthorizationServiceConfiguration(),
            is(notNullValue())
        );
        assertThat(
            state
                .getAuthorizationServiceConfiguration()
                .authorizationEndpoint.toString(),
            equalTo(authUri)
        );
        assertThat(
            state
                .getAuthorizationServiceConfiguration()
                .tokenEndpoint.toString(),
            equalTo(tokenUri)
        );
    }
}
