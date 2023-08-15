package com.strivacity.android.sdk;

import androidx.annotation.AnyThread;

import net.openid.appauth.AuthState;

public interface Storage {
    /**
     * This method is called when performing logout calls a full reset.
     */
    @AnyThread
    void clear();

    /**
     * It is called every time when the state is updated.
     *
     * @param state The auth state that should be stored
     */
    @AnyThread
    void setState(AuthState state);

    /**
     * Returns the auth state from the storage.
     *
     * @return The state from the storage
     */
    @AnyThread
    AuthState getState();
}
