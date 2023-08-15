package com.strivacity.android.sdk;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.Map;

public interface FlowResponseCallback {
    /**
     * This method is called when you call either {@link com.strivacity.android.sdk.AuthProvider#startFlow} or
     * {@link com.strivacity.android.sdk.AuthProvider#getAccessToken}.
     *
     * @param accessToken Contains the access token if it is present.
     * @param claims Contains the claims if it is present.
     */
    void success(
        @Nullable String accessToken,
        @Nullable Map<String, Object> claims
    );

    /**
     * This method is called when you call either {@link com.strivacity.android.sdk.AuthProvider#startFlow} or
     * {@link com.strivacity.android.sdk.AuthProvider#getAccessToken}. It contains the error message and what
     * caused the error.
     *
     * @param exception {@link com.strivacity.android.sdk.AuthFlowException} error
     */
    void failure(@NonNull AuthFlowException exception);
}
