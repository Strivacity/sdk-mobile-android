package com.strivacity.demoapp;

import android.content.Context;
import android.net.Uri;
import android.os.Bundle;

import androidx.appcompat.app.AppCompatActivity;
import androidx.lifecycle.ViewModelProvider;

import com.strivacity.android.sdk.AuthProvider;

public class AppActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_app);

        Context context = getApplicationContext();

        SharedViewModel viewModel = new ViewModelProvider(this)
            .get(SharedViewModel.class);
        viewModel
            .getProvider()
            .setValue(
                AuthProvider
                    .create(
                        context,
                        Uri.parse(context.getString(R.string.ISSUER)),
                        context.getString(R.string.CLIENT_ID),
                        Uri.parse(context.getString(R.string.REDIRECT_URI)),
                        new CustomStorageImpl(context, AppActivity.this)
                    )
                    .withScopes("profile", "email")
                    .withPostLogoutUri(
                        Uri.parse(context.getString(R.string.POST_LOGOUT_URI))
                    )
            );
    }
}
