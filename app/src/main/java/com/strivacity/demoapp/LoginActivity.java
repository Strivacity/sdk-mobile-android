package com.strivacity.demoapp;

import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

import com.strivacity.android.sdk.AuthFlowException;
import com.strivacity.android.sdk.AuthProvider;
import com.strivacity.android.sdk.FlowResponseCallback;

import java.util.Map;

public class LoginActivity extends AppCompatActivity {

    private static final String TAG = "DemoApp:Login";

    private TextView errorText;

    private AuthProvider provider;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);

        errorText = findViewById(R.id.errortext);
        errorText.setText(getIntent().getStringExtra("EXTRA_ERROR_TEXT"));

        provider = Provider.getProvider(getApplicationContext());

        provider.checkAuthenticated(isAuthenticated -> {
            if (isAuthenticated) {
                Log.i(TAG, "already authenticated");
                Intent mainIntent = new Intent(
                    getApplicationContext(),
                    MainActivity.class
                );
                startActivity(mainIntent);
            }
        });
    }

    public void startFlow(View view) {
        Log.i(TAG, "start flow");
        provider.startFlow(
            getApplicationContext(),
            new FlowResponseCallback() {
                @Override
                public void success(
                    @Nullable String accessToken,
                    @Nullable Map<String, Object> claims
                ) {
                    Log.d(TAG, "start flow success");

                    Intent mainIntent = new Intent(
                        getApplicationContext(),
                        MainActivity.class
                    );
                    startActivity(mainIntent);
                }

                @Override
                public void failure(@NonNull AuthFlowException exception) {
                    Log.d(TAG, "start flow failure");
                    errorText.setText(exception.toString());
                }
            }
        );
    }
}
