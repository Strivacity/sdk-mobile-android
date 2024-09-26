package com.strivacity.android.sdk;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;

import android.util.Log;

import androidx.core.util.Consumer;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.MockitoJUnitRunner;

import net.openid.appauth.AuthState;
import net.openid.appauth.AuthorizationException;
import net.openid.appauth.AuthorizationResponse;
import net.openid.appauth.TokenResponse;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

@RunWith(MockitoJUnitRunner.class)
public class AuthStateManagerTest {

    @Mock
    private Storage storage;

    @Mock
    private AuthState authState;

    private AuthStateManager authStateManager;

    private AutoCloseable autoCloseable;
    private MockedStatic<Log> logMockedStatic;

    private CompletableFuture<Void> waitForAsync;

    @Before
    public void setUp() {
        autoCloseable = MockitoAnnotations.openMocks(this);

        Mockito
            .doAnswer(ans -> {
                Consumer<AuthState> authStateConsumer = ans.getArgument(0);
                authStateConsumer.accept(authState);
                return null;
            })
            .when(storage)
            .getState(Mockito.any());

        logMockedStatic = Mockito.mockStatic(Log.class);
        logMockedStatic
            .when(() -> Log.i(Mockito.anyString(), Mockito.anyString()))
            .thenReturn(0);

        authStateManager = new AuthStateManager(storage);

        waitForAsync = new CompletableFuture<>();
    }

    @After
    public void tearDown() throws Exception {
        logMockedStatic.close();
        autoCloseable.close();
    }

    @Test
    public void getCurrentStateFromStorage()
        throws ExecutionException, InterruptedException, TimeoutException {
        authStateManager.getCurrentState(currentState -> {
            assertThat(currentState, equalTo(authState));
            waitForAsync.complete(null);
        });
        waitForAsync.get(10, TimeUnit.SECONDS);

        Mockito.verify(storage, Mockito.times(1)).getState(Mockito.any());
    }

    @Test
    public void getCurrentStateEmptyState()
        throws ExecutionException, InterruptedException, TimeoutException {
        Mockito
            .doAnswer(ans -> {
                Consumer<AuthState> authStateConsumer = ans.getArgument(0);
                authStateConsumer.accept(null);
                return null;
            })
            .when(storage)
            .getState(Mockito.any());

        authStateManager.getCurrentState(currentState -> {
            assertThat(currentState, not(equalTo(authState)));
            waitForAsync.complete(null);
        });
        waitForAsync.get(10, TimeUnit.SECONDS);
    }

    @Test
    public void getCurrentStateFromSavedState()
        throws ExecutionException, InterruptedException, TimeoutException {
        authStateManager.getCurrentState(currentState -> {});
        authStateManager.getCurrentState(currentState -> {
            assertThat(currentState, equalTo(authState));
            waitForAsync.complete(null);
        });
        waitForAsync.get(10, TimeUnit.SECONDS);

        Mockito
            .verify(storage, Mockito.times(1)) // NOTE: called in the first line of the test
            .getState(Mockito.any());
    }

    @Test
    public void setCurrentState()
        throws ExecutionException, InterruptedException, TimeoutException {
        authStateManager.setCurrentState(authState);
        Mockito
            .verify(storage, Mockito.times(1))
            .setState(Mockito.eq(authState));
        authStateManager.getCurrentState(currentState -> {
            assertThat(currentState, equalTo(authState));
            waitForAsync.complete(null);
        });
        waitForAsync.get(10, TimeUnit.SECONDS);

        Mockito.verify(storage, Mockito.times(0)).getState(Mockito.any());
    }

    @Test
    public void updateCurrentStateWithAuthorizationResponse()
        throws ExecutionException, InterruptedException, TimeoutException {
        AuthorizationResponse mockResponse = Mockito.mock(
            AuthorizationResponse.class
        );
        AuthorizationException mockException = Mockito.mock(
            AuthorizationException.class
        );
        authStateManager.updateCurrentState(mockResponse, mockException);
        Mockito
            .verify(authState, Mockito.times(1))
            .update(Mockito.eq(mockResponse), Mockito.eq(mockException));
        Mockito.verify(storage, Mockito.times(1)).getState(Mockito.any());
        authStateManager.getCurrentState(currentState -> {
            assertThat(currentState, equalTo(authState));
            waitForAsync.complete(null);
        });
        waitForAsync.get(10, TimeUnit.SECONDS);

        Mockito.verify(storage, Mockito.times(1)).getState(Mockito.any());
    }

    @Test
    public void updateCurrentStateWithTokenResponse()
        throws ExecutionException, InterruptedException, TimeoutException {
        TokenResponse mockResponse = Mockito.mock(TokenResponse.class);
        AuthorizationException mockException = Mockito.mock(
            AuthorizationException.class
        );
        authStateManager.updateCurrentState(mockResponse, mockException);
        Mockito
            .verify(authState, Mockito.times(1))
            .update(Mockito.eq(mockResponse), Mockito.eq(mockException));
        Mockito.verify(storage, Mockito.times(1)).getState(Mockito.any());
        authStateManager.getCurrentState(currentState -> {
            assertThat(currentState, equalTo(authState));
            waitForAsync.complete(null);
        });
        waitForAsync.get(10, TimeUnit.SECONDS);

        Mockito.verify(storage, Mockito.times(1)).getState(Mockito.any());
    }

    @Test
    public void resetCurrentState() {
        authStateManager.resetCurrentState();
        Mockito.verify(storage, Mockito.times(1)).clear();
        authStateManager.getCurrentState(state -> {});
        Mockito.verify(storage, Mockito.times(1)).getState(Mockito.any());
    }
}
