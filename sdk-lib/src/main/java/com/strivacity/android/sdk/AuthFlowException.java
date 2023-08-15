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
        String error,
        String errorDescription,
        Throwable rootCause
    ) {
        if (error == null && errorDescription == null) {
            return new AuthFlowException(
                null,
                rootCause.getMessage(),
                rootCause
            );
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
