package com.strivacity.demoapp;

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

    private static final String TAG = "DemoApp:AppActivity";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_app);

        SharedViewModel viewModel = new ViewModelProvider(this)
            .get(SharedViewModel.class);
        viewModel.getProvider().setValue(createAuthProvider());
    }

    private AuthProvider createAuthProvider() {
        Context context = getApplicationContext();
        Uri issuer = Uri.parse(context.getString(R.string.ISSUER));
        Uri redirectUri = Uri.parse(context.getString(R.string.REDIRECT_URI));
        Uri postLogoutUri = Uri.parse(
            context.getString(R.string.POST_LOGOUT_URI)
        );
        String clientId = context.getString(R.string.CLIENT_ID);

        return AuthProvider
            .create(
                context,
                issuer,
                clientId,
                redirectUri,
                null,
                sessionChangeCallback()
            )
            .withScopes("profile", "email")
            .withPostLogoutUri(postLogoutUri);
    }

    private FlowResponseCallback sessionChangeCallback() {
        return new FlowResponseCallback() {
            @Override
            public void success(
                @Nullable String accessToken,
                @Nullable Map<String, Object> claims
            ) {
                if (accessToken == null) {
                    Log.i(TAG, "Logout COMPLETED");
                    // user was logged out
                    navigate(R.id.action_mainFragment_to_loginFragment);
                } else {
                    Log.i(TAG, "Login COMPLETED successfully");
                    navigate(R.id.action_loginFragment_to_mainFragment);
                }
            }

            @Override
            public void failure(@NonNull AuthFlowException exception) {
                Log.i(TAG, "Login FAILED");
            }
        };
    }

    private void navigate(int actionId) {
        Navigation
            .findNavController(this, R.id.nav_host_fragment)
            .navigate(actionId);
    }
}
