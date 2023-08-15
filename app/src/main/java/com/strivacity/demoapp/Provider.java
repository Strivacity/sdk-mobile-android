package com.strivacity.demoapp;

import android.content.Context;
import android.net.Uri;

import com.strivacity.android.sdk.AuthProvider;

public class Provider {

    private static AuthProvider provider = null;

    public static AuthProvider getProvider(Context context) {
        if (provider == null) {
            provider =
                AuthProvider
                    .create(
                        context,
                        Uri.parse(context.getString(R.string.ISSUER)),
                        context.getString(R.string.CLIENT_ID),
                        Uri.parse(context.getString(R.string.REDIRECT_URI)),
                        null
                    )
                    .withScopes("profile", "email")
                    .withPostLogoutUri(
                        Uri.parse(context.getString(R.string.POST_LOGOUT_URI))
                    );
        }
        return provider;
    }
}
