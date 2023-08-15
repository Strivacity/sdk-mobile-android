package com.strivacity.android.sdk;

import android.app.Activity;
import android.util.Log;

import net.openid.appauth.AuthorizationException;
import net.openid.appauth.AuthorizationResponse;

public class AuthActivity extends Activity {

    private static final String TAG = "AuthActivity";

    @Override
    protected void onStart() {
        super.onStart();
        Log.i(TAG, "AuthActivity.onStart");

        AuthorizationResponse response = AuthorizationResponse.fromIntent(
            getIntent()
        );
        AuthorizationException exception = AuthorizationException.fromIntent(
            getIntent()
        );

        if (AuthProvider.INSTANCE == null) {
            Log.w(
                TAG,
                "AuthProvider is not initialized, use create to initialize it"
            );
            return;
        }

        AuthProvider.INSTANCE.authStateManager.updateCurrentState(
            response,
            exception
        );

        if (response != null) {
            Log.i(TAG, "authorization success");
            AuthProvider.INSTANCE.authActivityCallback.success(response);
        } else {
            Log.w(TAG, "authorization failed");
            if (exception != null) {
                AuthProvider.INSTANCE.authActivityCallback.failure(
                    AuthFlowException.of(
                        exception.error,
                        exception.errorDescription,
                        exception.getCause()
                    )
                );
            } else {
                AuthProvider.INSTANCE.authActivityCallback.failure(
                    AuthFlowException.UNEXPECTED
                );
            }
        }

        finish();
    }
}
