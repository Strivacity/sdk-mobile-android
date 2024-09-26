package com.strivacity.demoapp;

import android.os.Bundle;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.ViewModelProvider;
import androidx.navigation.Navigation;

import com.strivacity.android.sdk.AuthFlowException;
import com.strivacity.android.sdk.FlowResponseCallback;

import java.util.Map;

public class LoginFragment extends Fragment {

    private static final String TAG = "DemoApp:Login";

    @Override
    public View onCreateView(
        @NonNull LayoutInflater inflater,
        ViewGroup container,
        Bundle savedInstanceState
    ) {
        return inflater.inflate(R.layout.fragment_login, container, false);
    }

    @Override
    public void onViewCreated(
        @NonNull View view,
        @Nullable Bundle savedInstanceState
    ) {
        super.onViewCreated(view, savedInstanceState);

        TextView errorText = view.findViewById(R.id.errortext);
        if (savedInstanceState != null) {
            errorText.setText(savedInstanceState.getString("EXTRA_ERROR_TEXT"));
        }

        SharedViewModel viewModel = new ViewModelProvider(requireActivity())
            .get(SharedViewModel.class);
        viewModel
            .getProvider()
            .observe(
                getViewLifecycleOwner(),
                authProvider ->
                    view.post(() -> {
                        authProvider.checkAuthenticated(isAuthenticated -> {
                            if (isAuthenticated) {
                                Log.i(TAG, "already authenticated");
                                Navigation
                                    .findNavController(
                                        requireActivity(),
                                        R.id.nav_host_fragment
                                    )
                                    .navigate(
                                        R.id.action_loginFragment_to_mainFragment
                                    );
                            }
                        });

                        view
                            .findViewById(R.id.startFlow)
                            .setOnClickListener(v ->
                                authProvider.startFlow(
                                    requireContext(),
                                    new FlowResponseCallback() {
                                        @Override
                                        public void success(
                                            @Nullable String accessToken,
                                            @Nullable Map<String, Object> claims
                                        ) {
                                            Log.d(TAG, "start flow success");
                                            Navigation
                                                .findNavController(
                                                    requireActivity(),
                                                    R.id.nav_host_fragment
                                                )
                                                .navigate(
                                                    R.id.action_loginFragment_to_mainFragment
                                                );
                                        }

                                        @Override
                                        public void failure(
                                            @NonNull AuthFlowException exception
                                        ) {
                                            Log.d(TAG, "start flow failure");
                                            errorText.setText(
                                                exception.toString()
                                            );
                                        }
                                    }
                                )
                            );
                    })
            );
    }
}
