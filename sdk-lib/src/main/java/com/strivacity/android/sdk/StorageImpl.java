package com.strivacity.android.sdk;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

import org.json.JSONException;

import net.openid.appauth.AuthState;

class StorageImpl implements Storage {

    private static final String TAG = "StorageImpl";

    private static final String STORE_NAME =
        "com.strivacity.android.sdk.AuthState";

    private final SharedPreferences storage;

    public StorageImpl(Context context) {
        storage =
            context.getSharedPreferences(STORE_NAME, Context.MODE_PRIVATE);
    }

    @Override
    public void clear() {
        storage.edit().remove(STORE_NAME).apply();
    }

    @Override
    public void setState(AuthState state) throws IllegalStateException {
        SharedPreferences.Editor editor = storage.edit();
        if (state == null) {
            editor.remove(STORE_NAME);
        } else {
            editor.putString(STORE_NAME, state.jsonSerializeString());
        }
        if (!editor.commit()) {
            throw new IllegalStateException(
                "Failed to write state to shared prefs"
            );
        }
    }

    @Override
    public AuthState getState() {
        String state = storage.getString(STORE_NAME, null);
        if (state == null) {
            return null;
        }

        try {
            return AuthState.jsonDeserialize(state);
        } catch (JSONException ignored) {
            Log.i(TAG, "Failed to deserialize auth state");
            return null;
        }
    }
}
