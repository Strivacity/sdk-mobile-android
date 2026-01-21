package com.strivacity.demoapp;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.ViewModelProvider;
import androidx.navigation.Navigation;

import com.google.android.material.textfield.TextInputEditText;
import com.google.android.material.textfield.TextInputLayout;
import com.strivacity.android.sdk.AuthFlowException;
import com.strivacity.android.sdk.FlowResponseCallback;

import java.util.Collections;
import java.util.Map;
import java.util.Objects;

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

        final Context context = view.getContext();
        final Uri docsPage = Uri.parse(
            getString(R.string.docs_url_custom_audiences)
        );
        final Intent openActionsDocs = new Intent(Intent.ACTION_VIEW, docsPage);

        TextInputLayout textInputLayout = view.findViewById(
            R.id.text_input_layout_audiences
        );
        textInputLayout.setEndIconOnClickListener(v -> {
            try {
                context.startActivity(openActionsDocs);
            } catch (IllegalArgumentException ex) {
                Log.e(
                    "FirstFragment",
                    "Could not open Docs page for custom audiences",
                    ex
                );
                Toast
                    .makeText(
                        context,
                        R.string.toast_error_failed_open_intent,
                        Toast.LENGTH_SHORT
                    )
                    .show();
            }
        });

        TextView errorText = view.findViewById(R.id.errortext);
        if (savedInstanceState != null) {
            errorText.setText(savedInstanceState.getString("EXTRA_ERROR_TEXT"));
        }

        TextInputEditText audiencesInput = view.findViewById(
            R.id.text_input_audiences
        );

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
                            .setOnClickListener(v -> {
                                String audiencesInputText = Objects
                                    .requireNonNull(audiencesInput.getText())
                                    .toString();
                                String[] audiences = audiencesInputText.isBlank()
                                    ? null
                                    : audiencesInputText.split("\\s+");

                                authProvider
                                    .withAudiences(audiences)
                                    .startFlow(
                                        requireContext(),
                                        new FlowResponseCallback() {
                                            @Override
                                            public void success(
                                                @Nullable String accessToken,
                                                @Nullable Map<String, Object> claims
                                            ) {
                                                Log.d(
                                                    TAG,
                                                    "start flow success"
                                                );
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
                                                Log.d(
                                                    TAG,
                                                    "start flow failure"
                                                );
                                                errorText.setText(
                                                    exception.toString()
                                                );
                                            }
                                        },
                                        Collections.emptyMap()
                                    );
                            });
                    })
            );
    }
}
