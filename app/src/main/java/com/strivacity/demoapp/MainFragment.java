package com.strivacity.demoapp;

import android.os.Bundle;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TableLayout;
import android.widget.TableRow;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.ViewModelProvider;
import androidx.navigation.Navigation;

import com.strivacity.android.sdk.AuthFlowException;
import com.strivacity.android.sdk.FlowResponseCallback;

import java.util.Map;

public class MainFragment extends Fragment {

    private static final String TAG = "DemoApp:Main";

    @Override
    public View onCreateView(
        @NonNull LayoutInflater inflater,
        ViewGroup container,
        Bundle savedInstanceState
    ) {
        return inflater.inflate(R.layout.fragment_main, container, false);
    }

    @Override
    public void onViewCreated(
        @NonNull View view,
        @Nullable Bundle savedInstanceState
    ) {
        TextView accessTokenTextView = view.findViewById(R.id.accessToken);
        TableLayout claimTable = view.findViewById(R.id.table);

        SharedViewModel viewModel = new ViewModelProvider(requireActivity())
            .get(SharedViewModel.class);
        viewModel
            .getProvider()
            .observe(
                getViewLifecycleOwner(),
                authProvider ->
                    view.post(() -> {
                        view
                            .findViewById(R.id.logout)
                            .setOnClickListener(v -> {
                                Log.i(TAG, "logout");
                                accessTokenTextView.setText("");
                                claimTable.removeAllViews();
                                authProvider.logout(
                                    requireContext(),
                                    () -> {
                                        Log.i(TAG, "logout callback");
                                        Navigation
                                            .findNavController(
                                                requireActivity(),
                                                R.id.nav_host_fragment
                                            )
                                            .navigate(
                                                R.id.action_mainFragment_to_loginFragment
                                            );
                                    }
                                );
                            });

                        view
                            .findViewById(R.id.getLastClaims)
                            .setOnClickListener(v -> {
                                Log.i(TAG, "get last claims");
                                claimTable.removeAllViews();
                                authProvider.getLastRetrievedClaims(claims -> {
                                    if (claims != null) {
                                        Log.i(TAG, "there are claims");
                                        claims.forEach((s, o) -> {
                                            TableRow row = new TableRow(
                                                requireContext()
                                            );
                                            TextView key = new TextView(
                                                requireContext()
                                            );
                                            key.setText(s);
                                            row.addView(key);
                                            TextView value = new TextView(
                                                requireContext()
                                            );
                                            value.setText(o.toString());
                                            row.addView(value);
                                            claimTable.addView(row);
                                        });
                                    }
                                });
                            });

                        view
                            .findViewById(R.id.getAccessToken)
                            .setOnClickListener(v -> {
                                Log.i(TAG, "get access token");
                                accessTokenTextView.setText("");

                                authProvider.getAccessToken(
                                    new FlowResponseCallback() {
                                        @Override
                                        public void success(
                                            @Nullable String accessToken,
                                            @Nullable Map<String, Object> claims
                                        ) {
                                            Log.i(
                                                TAG,
                                                "get access token success"
                                            );
                                            accessTokenTextView.setText(
                                                accessToken
                                            );
                                        }

                                        @Override
                                        public void failure(
                                            @NonNull AuthFlowException exception
                                        ) {
                                            Log.i(
                                                TAG,
                                                "get access token failure"
                                            );
                                            accessTokenTextView.setText("");
                                            claimTable.removeAllViews();

                                            Bundle bundle = new Bundle();
                                            bundle.putString(
                                                "EXTRA_ERROR_TEXT",
                                                exception.toString()
                                            );
                                            Navigation
                                                .findNavController(
                                                    requireActivity(),
                                                    R.id.nav_host_fragment
                                                )
                                                .navigate(
                                                    R.id.action_mainFragment_to_loginFragment,
                                                    bundle
                                                );
                                        }
                                    }
                                );
                            });
                    })
            );
    }
}
