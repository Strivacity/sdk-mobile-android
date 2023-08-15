package com.strivacity.android.sdk;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

import org.json.JSONException;
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

@RunWith(MockitoJUnitRunner.class)
public class StorageImplTest {

    @Mock
    private SharedPreferences sharedPreferences;

    @Mock
    private AuthState authState;

    private Storage storage;

    private AutoCloseable autoCloseable;
    private MockedStatic<Log> logMockedStatic;

    @Before
    public void setUp() {
        autoCloseable = MockitoAnnotations.openMocks(this);

        Context mockContext = Mockito.mock(Context.class);

        Mockito
            .when(
                mockContext.getSharedPreferences(
                    Mockito.anyString(),
                    Mockito.anyInt()
                )
            )
            .thenReturn(sharedPreferences);

        logMockedStatic = Mockito.mockStatic(Log.class);
        logMockedStatic
            .when(() -> Log.i(Mockito.anyString(), Mockito.anyString()))
            .thenReturn(0);

        storage = new StorageImpl(mockContext);
    }

    @After
    public void tearDown() throws Exception {
        logMockedStatic.close();
        autoCloseable.close();
    }

    @Test
    public void getStateFromStorageFound() {
        Mockito
            .when(
                sharedPreferences.getString(
                    Mockito.anyString(),
                    Mockito.isNull()
                )
            )
            .thenReturn("json string");

        MockedStatic<AuthState> mockedState = Mockito.mockStatic(
            AuthState.class
        );
        mockedState
            .when(() -> AuthState.jsonDeserialize(Mockito.eq("json string")))
            .thenReturn(authState);

        AuthState stateFromStorage = storage.getState();
        assertThat(stateFromStorage, equalTo(authState));

        mockedState.close();
    }

    @Test
    public void getStateFromStorageNotFound() {
        Mockito
            .when(
                sharedPreferences.getString(
                    Mockito.anyString(),
                    Mockito.isNull()
                )
            )
            .thenReturn(null);

        AuthState stateFromStorage = storage.getState();
        assertThat(stateFromStorage, is(nullValue()));
    }

    @Test
    public void getStateFromStorageExceptionThrownDuringJsonDeserialization() {
        Mockito
            .when(
                sharedPreferences.getString(
                    Mockito.anyString(),
                    Mockito.isNull()
                )
            )
            .thenReturn("json string");

        MockedStatic<AuthState> mockedState = Mockito.mockStatic(
            AuthState.class
        );
        mockedState
            .when(() -> AuthState.jsonDeserialize(Mockito.anyString()))
            .thenThrow(new JSONException(""));

        AuthState stateFromStorage = storage.getState();
        assertThat(stateFromStorage, is(nullValue()));

        mockedState.close();
    }

    @Test
    public void setStateSuccess() {
        SharedPreferences.Editor mockEditor = Mockito.mock();
        Mockito.when(sharedPreferences.edit()).thenReturn(mockEditor);
        Mockito.when(mockEditor.commit()).thenReturn(true);

        Mockito
            .when(authState.jsonSerializeString())
            .thenReturn("auth state json value");

        storage.setState(authState);

        Mockito
            .verify(mockEditor, Mockito.times(1))
            .putString(
                Mockito.anyString(),
                Mockito.eq("auth state json value")
            );
    }

    @Test
    public void setStateNull() {
        SharedPreferences.Editor mockEditor = Mockito.mock();
        Mockito.when(sharedPreferences.edit()).thenReturn(mockEditor);
        Mockito.when(mockEditor.commit()).thenReturn(true);

        storage.setState(null);

        Mockito
            .verify(mockEditor, Mockito.times(1))
            .remove(Mockito.anyString());
    }

    @Test(expected = IllegalStateException.class)
    public void setStateThrowsException() {
        SharedPreferences.Editor mockEditor = Mockito.mock();
        Mockito.when(sharedPreferences.edit()).thenReturn(mockEditor);
        Mockito.when(mockEditor.commit()).thenReturn(false);

        storage.setState(authState);
    }

    @Test
    public void clear() {
        SharedPreferences.Editor mockEditor = Mockito.mock();
        Mockito.when(sharedPreferences.edit()).thenReturn(mockEditor);
        Mockito
            .when(mockEditor.remove(Mockito.anyString()))
            .thenReturn(mockEditor);

        storage.clear();

        Mockito
            .verify(mockEditor, Mockito.times(1))
            .remove(Mockito.anyString());

        Mockito.verify(mockEditor, Mockito.times(1)).apply();
    }
}
