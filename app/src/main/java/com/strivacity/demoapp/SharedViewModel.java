package com.strivacity.demoapp;

import androidx.lifecycle.MutableLiveData;
import androidx.lifecycle.ViewModel;

import com.strivacity.android.sdk.AuthProvider;

public class SharedViewModel extends ViewModel {

    private final MutableLiveData<AuthProvider> provider = new MutableLiveData<>();

    public MutableLiveData<AuthProvider> getProvider() {
        return provider;
    }
}
