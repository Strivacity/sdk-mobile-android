package com.strivacity.android.sdk;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;

import android.util.Log;

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

@RunWith(MockitoJUnitRunner.class)
public class AuthStateManagerTest {

    @Mock
    private Storage storage;

    @Mock
    private AuthState authState;

    private AuthStateManager authStateManager;

    private AutoCloseable autoCloseable;
    private MockedStatic<Log> logMockedStatic;

    @Before
    public void setUp() {
        autoCloseable = MockitoAnnotations.openMocks(this);

        Mockito.when(storage.getState()).thenReturn(authState);

        logMockedStatic = Mockito.mockStatic(Log.class);
        logMockedStatic
            .when(() -> Log.i(Mockito.anyString(), Mockito.anyString()))
            .thenReturn(0);

        authStateManager = new AuthStateManager(storage);
    }

    @After
    public void tearDown() throws Exception {
        logMockedStatic.close();
        autoCloseable.close();
    }

    @Test
    public void getCurrentStateFromStorage() {
        AuthState currentState = authStateManager.getCurrentState();
        assertThat(currentState, equalTo(authState));
        Mockito.verify(storage, Mockito.times(1)).getState();
    }

    @Test
    public void getCurrentStateEmptyState() {
        Mockito.when(storage.getState()).thenReturn(null);

        AuthState currentState = authStateManager.getCurrentState();
        assertThat(currentState, not(equalTo(authState)));
    }

    @Test
    public void getCurrentStateFromSavedState() {
        authStateManager.getCurrentState();
        AuthState currentState = authStateManager.getCurrentState();
        assertThat(currentState, equalTo(authState));
        Mockito
            .verify(storage, Mockito.times(1)) // NOTE: called in the first line of the test
            .getState();
    }

    @Test
    public void setCurrentState() {
        authStateManager.setCurrentState(authState);
        Mockito
            .verify(storage, Mockito.times(1))
            .setState(Mockito.eq(authState));
        AuthState currentState = authStateManager.getCurrentState();
        assertThat(currentState, equalTo(authState));
        Mockito.verify(storage, Mockito.times(0)).getState();
    }

    @Test
    public void updateCurrentStateWithAuthorizationResponse() {
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
        Mockito.verify(storage, Mockito.times(1)).getState();
        AuthState currentState = authStateManager.getCurrentState();
        assertThat(currentState, equalTo(authState));
        Mockito.verify(storage, Mockito.times(1)).getState();
    }

    @Test
    public void updateCurrentStateWithTokenResponse() {
        TokenResponse mockResponse = Mockito.mock(TokenResponse.class);
        AuthorizationException mockException = Mockito.mock(
            AuthorizationException.class
        );
        authStateManager.updateCurrentState(mockResponse, mockException);
        Mockito
            .verify(authState, Mockito.times(1))
            .update(Mockito.eq(mockResponse), Mockito.eq(mockException));
        Mockito.verify(storage, Mockito.times(1)).getState();
        AuthState currentState = authStateManager.getCurrentState();
        assertThat(currentState, equalTo(authState));
        Mockito.verify(storage, Mockito.times(1)).getState();
    }

    @Test
    public void resetCurrentState() {
        authStateManager.resetCurrentState();
        Mockito.verify(storage, Mockito.times(1)).clear();
        authStateManager.getCurrentState();
        Mockito.verify(storage, Mockito.times(1)).getState();
    }
}
