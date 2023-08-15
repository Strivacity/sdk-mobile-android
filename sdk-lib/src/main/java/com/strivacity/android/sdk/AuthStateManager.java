package com.strivacity.android.sdk;

import android.util.Log;

import androidx.annotation.AnyThread;

import net.openid.appauth.AuthState;
import net.openid.appauth.AuthorizationException;
import net.openid.appauth.AuthorizationResponse;
import net.openid.appauth.TokenResponse;

import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;

class AuthStateManager {

    private static final String TAG = "AuthStateManager";

    private final Storage storage;
    private final ReentrantLock storageLock;
    private final AtomicReference<AuthState> currentState;

    public AuthStateManager(Storage storage) {
        Log.i(TAG, "Creating AuthStageManager instance");

        this.storage = storage;

        storageLock = new ReentrantLock();
        currentState = new AtomicReference<>();
    }

    @AnyThread
    public AuthState getCurrentState() {
        if (currentState.get() != null) {
            Log.i(TAG, "currentState found");
            return currentState.get();
        }

        storageLock.lock();
        AuthState storageState = storage.getState();
        storageLock.unlock();

        if (storageState == null) {
            Log.i(TAG, "creating new empty state");
            storageState = new AuthState();
        }
        currentState.set(storageState);

        return storageState;
    }

    @AnyThread
    public void setCurrentState(AuthState state) {
        storageLock.lock();
        storage.setState(state);
        storageLock.unlock();

        currentState.set(state);
    }

    @AnyThread
    public void updateCurrentState(
        AuthorizationResponse response,
        AuthorizationException exception
    ) {
        AuthState current = getCurrentState();
        current.update(response, exception);
        setCurrentState(current);
    }

    @AnyThread
    public void updateCurrentState(
        TokenResponse response,
        AuthorizationException exception
    ) {
        AuthState current = getCurrentState();
        current.update(response, exception);
        setCurrentState(current);
    }

    @AnyThread
    public void resetCurrentState() {
        storageLock.lock();
        storage.clear();
        storageLock.unlock();

        currentState.set(null);
    }
}
