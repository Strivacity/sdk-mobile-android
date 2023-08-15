package com.strivacity.demoapp;

import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.TableLayout;
import android.widget.TableRow;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

import com.strivacity.android.sdk.AuthFlowException;
import com.strivacity.android.sdk.AuthProvider;
import com.strivacity.android.sdk.FlowResponseCallback;

import java.util.Map;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "DemoApp:Main";

    private AuthProvider provider;

    private TextView accessTokenTextView;
    private TableLayout claimTable;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        accessTokenTextView = findViewById(R.id.accessToken);
        claimTable = findViewById(R.id.table);

        provider = Provider.getProvider(getApplicationContext());
    }

    public void logout(View view) {
        Log.i(TAG, "logout");
        accessTokenTextView.setText("");
        claimTable.removeAllViews();
        provider.logout(
            getApplicationContext(),
            () -> {
                Log.i(TAG, "logout callback");
                Intent intent = new Intent(
                    getApplicationContext(),
                    LoginActivity.class
                );
                startActivity(intent);
            }
        );
    }

    public void getLastClaims(View view) {
        Log.i(TAG, "get last claims");
        claimTable.removeAllViews();
        Map<String, Object> claims = provider.getLastRetrievedClaims();
        if (claims != null) {
            Log.i(TAG, "there are claims");
            claims.forEach((s, o) -> {
                TableRow row = new TableRow(getApplicationContext());
                TextView key = new TextView(getApplicationContext());
                key.setText(s);
                row.addView(key);
                TextView value = new TextView(getApplicationContext());
                value.setText(o.toString());
                row.addView(value);
                claimTable.addView(row);
            });
        }
    }

    public void getAccessToken(View view) {
        Log.i(TAG, "get access token");
        accessTokenTextView.setText("");

        provider.getAccessToken(
            new FlowResponseCallback() {
                @Override
                public void success(
                    @Nullable String accessToken,
                    @Nullable Map<String, Object> claims
                ) {
                    Log.i(TAG, "get access token success");
                    accessTokenTextView.setText(accessToken);
                }

                @Override
                public void failure(@NonNull AuthFlowException exception) {
                    Log.i(TAG, "get access token failure");
                    accessTokenTextView.setText("");
                    claimTable.removeAllViews();

                    Intent intent = new Intent(
                        getApplicationContext(),
                        LoginActivity.class
                    );
                    intent.putExtra("EXTRA_ERROR_TEXT", exception.toString());
                    startActivity(intent);
                }
            }
        );
    }
}
