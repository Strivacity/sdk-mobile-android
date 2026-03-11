package com.strivacity.android.sdk;

import android.app.Activity;
import android.util.Log;

public class AuthActivity extends Activity {

    private static final String TAG = "AuthActivity";

    @Override
    protected void onStart() {
        super.onStart();
        Log.i(TAG, "AuthActivity.onStart");

        if (AuthProvider.INSTANCE == null) {
            Log.w(
                TAG,
                "AuthProvider is not initialized, use create to initialize it"
            );
            return;
        }

        AuthProvider.INSTANCE.continueAuthorization(getIntent());

        finish();
    }
}
