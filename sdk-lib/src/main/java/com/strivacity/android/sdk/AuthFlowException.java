package com.strivacity.android.sdk;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

public class AuthFlowException extends Exception {

    static final AuthFlowException UNEXPECTED;

    static {
        UNEXPECTED =
            of("Unexpected error", "An unexpected error happened", null);
    }

    private final String error;
    private final String errorDescription;

    private AuthFlowException(
        String error,
        String errorDescription,
        Throwable cause
    ) {
        super(cause);
        this.error = error;
        this.errorDescription = errorDescription;
    }

    static AuthFlowException of(
        @Nullable String error,
        @Nullable String errorDescription,
        @Nullable Throwable rootCause
    ) {
        if (error == null && errorDescription == null) {
            @Nullable
            final String causeMessage = rootCause == null
                ? "Unknown cause"
                : rootCause.getMessage();
            return new AuthFlowException(null, causeMessage, rootCause);
        }
        return new AuthFlowException(error, errorDescription, rootCause);
    }

    static AuthFlowException unsupportedAuthenticationMethod(
        String method,
        Throwable rootCause
    ) {
        return new AuthFlowException(
            "Unsupported authentication method",
            method,
            rootCause
        );
    }

    static AuthFlowException browserIntentResolutionFailed(Throwable rootCase) {
        return new AuthFlowException(
            "BrowserIntentResolutionFailed",
            "No compatible browser found on device",
            rootCase
        );
    }

    @Nullable
    @SuppressWarnings("unused")
    public String getError() {
        return error;
    }

    @Nullable
    @SuppressWarnings("unused")
    public String getErrorDescription() {
        return errorDescription;
    }

    @Override
    @NonNull
    public String toString() {
        return String.format("%s - %s", error, errorDescription);
    }
}
