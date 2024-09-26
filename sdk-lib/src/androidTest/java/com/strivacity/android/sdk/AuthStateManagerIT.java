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

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

@RunWith(AndroidJUnit4.class)
public class AuthStateManagerIT {

    private static final String AUTH_ENDPOINT = "http://example.com/auth";
    private static final String TOKEN_ENDPOINT = "http://example.com/token";

    private AuthStateManager authStateManager;
    private Storage storage;

    private CompletableFuture<Void> waitForAsync;

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

        waitForAsync = new CompletableFuture<>();
    }

    @Test
    public void getCurrentStateFromStorage()
        throws ExecutionException, InterruptedException, TimeoutException {
        authStateManager.getCurrentState(authState -> {
            assertAuthStateConfigUrls(authState, AUTH_ENDPOINT, TOKEN_ENDPOINT);
            waitForAsync.complete(null);
        });
        waitForAsync.get(10, TimeUnit.SECONDS);
    }

    @Test
    public void getCurrentStateFromStorageButItIsEmpty()
        throws ExecutionException, InterruptedException, TimeoutException {
        storage.setState(null);
        authStateManager.getCurrentState(authState -> {
            assertThat(
                authState.getAuthorizationServiceConfiguration(),
                is(nullValue())
            );
            waitForAsync.complete(null);
        });
        waitForAsync.get(10, TimeUnit.SECONDS);
    }

    @Test
    public void getCurrentState()
        throws ExecutionException, InterruptedException, TimeoutException {
        authStateManager.getCurrentState(authState -> {
            assertAuthStateConfigUrls(authState, AUTH_ENDPOINT, TOKEN_ENDPOINT);
            storage.setState(new AuthState());
            final CompletableFuture<Void> innerWaitForAsync = new CompletableFuture<>();
            authStateManager.getCurrentState(authState1 -> {
                assertAuthStateConfigUrls(
                    authState1,
                    AUTH_ENDPOINT,
                    TOKEN_ENDPOINT
                );
                innerWaitForAsync.complete(null);
            });
            try {
                innerWaitForAsync.get(10, TimeUnit.SECONDS);
            } catch (Exception e) {
                waitForAsync.completeExceptionally(e);
            }
            waitForAsync.complete(null);
        });
        waitForAsync.get(10, TimeUnit.SECONDS);
    }

    @Test
    public void setCurrentState()
        throws ExecutionException, InterruptedException, TimeoutException {
        String newAuthUri = "http://new-domain/auth";
        String newTokenUri = "http://new-domain/token";

        AuthorizationServiceConfiguration configuration = new AuthorizationServiceConfiguration(
            Uri.parse(newAuthUri),
            Uri.parse(newTokenUri)
        );
        AuthState state = new AuthState(configuration);

        authStateManager.setCurrentState(state);

        authStateManager.getCurrentState(authState -> {
            assertAuthStateConfigUrls(authState, newAuthUri, newTokenUri);
            waitForAsync.complete(null);
        });
        waitForAsync.get(10, TimeUnit.SECONDS);
        waitForAsync = new CompletableFuture<>();
        storage.getState(authState -> {
            assertAuthStateConfigUrls(authState, newAuthUri, newTokenUri);
            waitForAsync.complete(null);
        });
        waitForAsync.get(10, TimeUnit.SECONDS);
    }

    @Test
    public void updateCurrentStateAuthResponse()
        throws ExecutionException, InterruptedException, TimeoutException {
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

        authStateManager.getCurrentState(authState -> {
            assertAuthStateConfigUrls(authState, AUTH_ENDPOINT, TOKEN_ENDPOINT);
            assertThat(authState.getAccessToken(), equalTo("access_token"));
            assertThat(authState.getIdToken(), equalTo("id_token"));

            CompletableFuture<Void> innerWaitForAsync = new CompletableFuture<>();
            storage.getState(authState1 -> {
                assertAuthStateConfigUrls(
                    authState1,
                    AUTH_ENDPOINT,
                    TOKEN_ENDPOINT
                );
                assertThat(
                    authState1.getAccessToken(),
                    equalTo("access_token")
                );
                assertThat(authState1.getIdToken(), equalTo("id_token"));
                innerWaitForAsync.complete(null);
            });
            try {
                innerWaitForAsync.get(10, TimeUnit.SECONDS);
            } catch (Exception e) {
                waitForAsync.completeExceptionally(e);
            }
            waitForAsync.complete(null);
        });
        waitForAsync.get(10, TimeUnit.SECONDS);
    }

    @Test
    public void updateCurrentStateAuthResponseException()
        throws ExecutionException, InterruptedException, TimeoutException {
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

        authStateManager.getCurrentState(authState -> {
            assertAuthStateConfigUrls(authState, AUTH_ENDPOINT, TOKEN_ENDPOINT);
            assertThat(
                authState.getAuthorizationException(),
                is(notNullValue())
            );
            assertThat(
                authState.getAuthorizationException().error,
                equalTo("error")
            );
            assertThat(
                authState.getAuthorizationException().errorDescription,
                equalTo("error_description")
            );
            assertThat(
                authState.getAuthorizationException().code,
                equalTo(1000)
            );

            CompletableFuture<Void> innerWaitForAsync = new CompletableFuture<>();
            storage.getState(authState1 -> {
                assertAuthStateConfigUrls(
                    authState1,
                    AUTH_ENDPOINT,
                    TOKEN_ENDPOINT
                );
                assertThat(
                    authState1.getAuthorizationException(),
                    is(notNullValue())
                );
                assertThat(
                    authState1.getAuthorizationException().error,
                    equalTo("error")
                );
                assertThat(
                    authState1.getAuthorizationException().errorDescription,
                    equalTo("error_description")
                );
                assertThat(
                    authState1.getAuthorizationException().code,
                    equalTo(1000)
                );
                innerWaitForAsync.complete(null);
            });
            try {
                innerWaitForAsync.get(10, TimeUnit.SECONDS);
            } catch (Exception e) {
                waitForAsync.completeExceptionally(e);
            }
            waitForAsync.complete(null);
        });
        waitForAsync.get(10, TimeUnit.SECONDS);
    }

    @Test
    public void updateCurrentStateTokenResponse()
        throws ExecutionException, InterruptedException, TimeoutException {
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

        authStateManager.getCurrentState(authState -> {
            assertAuthStateConfigUrls(authState, AUTH_ENDPOINT, TOKEN_ENDPOINT);
            assertThat(authState.getAccessToken(), equalTo("access_token"));
            assertThat(authState.getIdToken(), equalTo("id_token"));

            CompletableFuture<Void> innerWaitForAsync = new CompletableFuture<>();
            storage.getState(authState1 -> {
                assertAuthStateConfigUrls(
                    authState1,
                    AUTH_ENDPOINT,
                    TOKEN_ENDPOINT
                );
                assertThat(
                    authState1.getAccessToken(),
                    equalTo("access_token")
                );
                assertThat(authState1.getIdToken(), equalTo("id_token"));
                innerWaitForAsync.complete(null);
            });
            try {
                innerWaitForAsync.get(10, TimeUnit.SECONDS);
            } catch (Exception e) {
                waitForAsync.completeExceptionally(e);
            }
            waitForAsync.complete(null);
        });
        waitForAsync.get(10, TimeUnit.SECONDS);
    }

    @Test
    public void updateCurrentStateTokenResponseException()
        throws ExecutionException, InterruptedException, TimeoutException {
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

        authStateManager.getCurrentState(authState -> {
            assertAuthStateConfigUrls(authState, AUTH_ENDPOINT, TOKEN_ENDPOINT);
            assertThat(
                authState.getAuthorizationException(),
                is(notNullValue())
            );
            assertThat(
                authState.getAuthorizationException().error,
                equalTo("error")
            );
            assertThat(
                authState.getAuthorizationException().errorDescription,
                equalTo("error_description")
            );
            assertThat(
                authState.getAuthorizationException().code,
                equalTo(1000)
            );

            CompletableFuture<Void> innerWaitForAsync = new CompletableFuture<>();
            storage.getState(authState1 -> {
                assertAuthStateConfigUrls(
                    authState1,
                    AUTH_ENDPOINT,
                    TOKEN_ENDPOINT
                );
                assertThat(
                    authState1.getAuthorizationException(),
                    is(notNullValue())
                );
                assertThat(
                    authState1.getAuthorizationException().error,
                    equalTo("error")
                );
                assertThat(
                    authState1.getAuthorizationException().errorDescription,
                    equalTo("error_description")
                );
                assertThat(
                    authState1.getAuthorizationException().code,
                    equalTo(1000)
                );
                innerWaitForAsync.complete(null);
            });
            try {
                innerWaitForAsync.get(10, TimeUnit.SECONDS);
            } catch (Exception e) {
                waitForAsync.completeExceptionally(e);
            }
            waitForAsync.complete(null);
        });
        waitForAsync.get(10, TimeUnit.SECONDS);
    }

    @Test
    public void resetCurrentState()
        throws ExecutionException, InterruptedException, TimeoutException {
        authStateManager.resetCurrentState();

        storage.getState(authState -> {
            assertThat(authState, is(nullValue()));
            waitForAsync.complete(null);
        });
        waitForAsync.get(10, TimeUnit.SECONDS);

        waitForAsync = new CompletableFuture<>();
        authStateManager.getCurrentState(authState -> {
            assertThat(
                authState.getAuthorizationServiceConfiguration(),
                is(nullValue())
            );
            waitForAsync.complete(null);
        });
        waitForAsync.get(10, TimeUnit.SECONDS);
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
