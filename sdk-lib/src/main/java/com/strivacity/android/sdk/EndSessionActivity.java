package com.strivacity.android.sdk;

import android.app.Activity;
import android.util.Log;

public class EndSessionActivity extends Activity {

    private static final String TAG = "EndSessionActivity";

    @Override
    protected void onStart() {
        super.onStart();
        if (AuthProvider.INSTANCE == null) {
            Log.w(
                TAG,
                "AuthProvider is not initialized, use create to initialize it"
            );
            return;
        }
        AuthProvider.INSTANCE.endSessionActivityCallback.finished();
        finish();
    }
}
