package com.strivacity.demoapp;

import android.app.Activity;
import android.content.Context;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.lifecycle.ViewModelProvider;
import androidx.navigation.Navigation;

import com.strivacity.android.sdk.AuthFlowException;
import com.strivacity.android.sdk.AuthProvider;
import com.strivacity.android.sdk.FlowResponseCallback;

import java.util.Map;

public class AppActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_app);

        Context context = getApplicationContext();
        final Activity activity = this;

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
                        new CustomStorageImpl(context, AppActivity.this),
                        new FlowResponseCallback() {
                            @Override
                            public void success(
                                @Nullable String accessToken,
                                @Nullable Map<String, Object> claims
                            ) {
                                if (accessToken == null) {
                                    Log.i(TAG, "Logout COMPLETED");
                                    // user was logged out
                                    Navigation
                                        .findNavController(
                                            activity,
                                            R.id.nav_host_fragment
                                        )
                                        .navigate(
                                            R.id.action_mainFragment_to_loginFragment
                                        );
                                } else {
                                    Log.i(TAG, "Login COMPLETED successfully");
                                    Navigation
                                        .findNavController(
                                            activity,
                                            R.id.nav_host_fragment
                                        )
                                        .navigate(
                                            R.id.action_loginFragment_to_mainFragment
                                        );
                                }
                            }

                            @Override
                            public void failure(
                                @NonNull AuthFlowException exception
                            ) {
                                Log.i(TAG, "Login FAILED");
                            }
                        }
                    )
                    .withScopes("profile", "email")
                    .withPostLogoutUri(
                        Uri.parse(context.getString(R.string.POST_LOGOUT_URI))
                    )
            );
    }

    static final String TAG = "AppActivity";
}
