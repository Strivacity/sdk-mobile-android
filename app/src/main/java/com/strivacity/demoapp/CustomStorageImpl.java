package com.strivacity.demoapp;

import static androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;
import androidx.core.util.Consumer;

import com.google.gson.Gson;
import com.strivacity.android.sdk.Storage;

import org.json.JSONException;

import net.openid.appauth.AuthState;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.concurrent.Executor;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class CustomStorageImpl implements Storage {

    private static final String TAG = "CustomStorageImpl";

    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String ENCRYPTION_BLOCK_MODE =
        KeyProperties.BLOCK_MODE_GCM;
    private static final String ENCRYPTION_PADDING =
        KeyProperties.ENCRYPTION_PADDING_NONE;
    private static final String ENCRYPTION_ALGORITHM =
        KeyProperties.KEY_ALGORITHM_AES;
    private static final int KEY_SIZE = 256;
    private static final String KEY_NAME = "com.strivacity.android.sdk.key";

    private static final String STORE_NAME =
        "com.strivacity.android.sdk.AuthState";

    private final SharedPreferences storage;
    private final AppCompatActivity activity;
    private final Executor executor;
    private final BiometricManager biometricManager;
    private final BiometricPrompt.PromptInfo promptInfo;
    private final Gson gson;

    public CustomStorageImpl(Context context, AppCompatActivity activity) {
        this.activity = activity;
        this.executor = ContextCompat.getMainExecutor(context);
        this.biometricManager = BiometricManager.from(context);
        storage =
            context.getSharedPreferences(STORE_NAME, Context.MODE_PRIVATE);
        gson = new Gson();
        promptInfo =
            new BiometricPrompt.PromptInfo.Builder()
                .setTitle("Biometric Authentication")
                .setSubtitle("Log in using your biometric credential")
                .setNegativeButtonText("Use account password")
                .build();
    }

    @Override
    public void clear() {
        storage.edit().remove(STORE_NAME).apply();
    }

    @Override
    public void setState(AuthState state) throws IllegalStateException {
        SharedPreferences.Editor editor = storage.edit();
        if (state == null) {
            editor.remove(STORE_NAME);
            if (!editor.commit()) {
                throw new IllegalStateException(
                    "Failed to write state to shared prefs"
                );
            }
        } else {
            try {
                authenticateToEncrypt(state);
            } catch (Exception e) {
                throw new IllegalStateException("Failed to encrypt state", e);
            }
        }
    }

    @Override
    public void getState(Consumer<AuthState> authStateConsumer) {
        Log.i(TAG, "get state from storage");
        String state = storage.getString(STORE_NAME, null);
        if (state == null) {
            Log.i(TAG, "storage state is null");
            authStateConsumer.accept(null);
            return;
        }

        try {
            authenticateToDecrypt(authStateConsumer, state);
        } catch (Exception e) {
            Log.i(TAG, "error happened: " + e.getMessage());
            authStateConsumer.accept(null);
        }
    }

    private void authenticateToEncrypt(AuthState authState) throws Exception {
        final Cipher cipher = getCipher();
        final SecretKey secretKey = getOrCreateSecretKey();
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        SharedPreferences.Editor editor = storage.edit();
        try {
            editor.putString(
                STORE_NAME,
                gson.toJson(encryptData(cipher, authState))
            );
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
        if (!editor.commit()) {
            throw new IllegalStateException(
                "Failed to write state to shared prefs"
            );
        }
    }

    private void authenticateToDecrypt(
        Consumer<AuthState> authStateConsumer,
        String encryptedData
    ) throws Exception {
        canAuthenticate();

        EncryptedData dataClass = gson.fromJson(
            encryptedData,
            EncryptedData.class
        );

        final Cipher cipher = getCipher();
        final SecretKey secretKey = getOrCreateSecretKey();
        cipher.init(
            Cipher.DECRYPT_MODE,
            secretKey,
            new GCMParameterSpec(128, dataClass.getIv())
        );

        BiometricPrompt biometricPrompt = new BiometricPrompt(
            activity,
            executor,
            createBiometricCallback(
                authenticationResult -> {
                    if (
                        authenticationResult.getCryptoObject() == null ||
                        authenticationResult.getCryptoObject().getCipher() ==
                        null
                    ) {
                        throw new RuntimeException(
                            "Crypto object is not defined"
                        );
                    }
                    SharedPreferences.Editor editor = storage.edit();

                    try {
                        String stateAsJson = decryptData(
                            dataClass.getCiphertext(),
                            authenticationResult.getCryptoObject().getCipher()
                        );
                        AuthState authState = AuthState.jsonDeserialize(
                            stateAsJson
                        );
                        authStateConsumer.accept(authState);
                    } catch (
                        IllegalBlockSizeException
                        | BadPaddingException
                        | JSONException e
                    ) {
                        throw new RuntimeException(e);
                    }

                    if (!editor.commit()) {
                        throw new IllegalStateException(
                            "Failed to write state to shared prefs"
                        );
                    }
                },
                unused -> authStateConsumer.accept(null)
            )
        );
        biometricPrompt.authenticate(
            promptInfo,
            new BiometricPrompt.CryptoObject(cipher)
        );
    }

    private void canAuthenticate() throws Exception {
        int authenticationResult = biometricManager.canAuthenticate(
            BIOMETRIC_STRONG
        );
        if (authenticationResult == BiometricManager.BIOMETRIC_SUCCESS) {
            Log.i(TAG, "Biometric success");
            return;
        }
        switch (authenticationResult) {
            case BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE:
                Log.i(TAG, "Biometric error hw unavailable");
            case BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED:
                Log.i(TAG, "Biometric error none enrolled");
            case BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE:
                Log.i(TAG, "Biometric error no hardware");
            case BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED:
                Log.i(TAG, "Biometric error security update required");
            case BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED:
                Log.i(TAG, "Biometric error unsupported");
            case BiometricManager.BIOMETRIC_STATUS_UNKNOWN:
                Log.i(TAG, "Biometric status unknown");
        }
        throw new Exception();
    }

    private BiometricPrompt.AuthenticationCallback createBiometricCallback(
        Consumer<BiometricPrompt.AuthenticationResult> successCallback,
        Consumer<Void> errorCallback
    ) {
        return new BiometricPrompt.AuthenticationCallback() {
            @Override
            public void onAuthenticationError(
                int errorCode,
                @NonNull CharSequence errString
            ) {
                Log.i(TAG, "Biometric authentication error");
                errorCallback.accept(null);
            }

            @Override
            public void onAuthenticationSucceeded(
                @NonNull BiometricPrompt.AuthenticationResult result
            ) {
                Log.i(TAG, "Biometric authentication succeeded");
                successCallback.accept(result);
            }

            @Override
            public void onAuthenticationFailed() {
                Log.i(TAG, "Biometric authentication failed");
                errorCallback.accept(null);
            }
        };
    }

    private EncryptedData encryptData(Cipher cipher, AuthState authState)
        throws IllegalBlockSizeException, BadPaddingException {
        byte[] ciphertext = cipher.doFinal(
            authState.jsonSerializeString().getBytes(StandardCharsets.UTF_8)
        );
        return new EncryptedData(ciphertext, cipher.getIV());
    }

    private String decryptData(byte[] ciphertext, Cipher cipher)
        throws IllegalBlockSizeException, BadPaddingException {
        byte[] plaintext = cipher.doFinal(ciphertext);
        return new String(plaintext, StandardCharsets.UTF_8);
    }

    private Cipher getCipher()
        throws NoSuchPaddingException, NoSuchAlgorithmException {
        final String transformation =
            ENCRYPTION_ALGORITHM +
            "/" +
            ENCRYPTION_BLOCK_MODE +
            "/" +
            ENCRYPTION_PADDING;
        return Cipher.getInstance(transformation);
    }

    private SecretKey getOrCreateSecretKey()
        throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, UnrecoverableKeyException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);
        Key key = keyStore.getKey(KEY_NAME, null);
        if (key != null) {
            return (SecretKey) key;
        }

        KeyGenParameterSpec.Builder paramsBuilder = new KeyGenParameterSpec.Builder(
            KEY_NAME,
            KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT
        );
        paramsBuilder.setBlockModes(ENCRYPTION_BLOCK_MODE);
        paramsBuilder.setEncryptionPaddings(ENCRYPTION_PADDING);
        paramsBuilder.setKeySize(KEY_SIZE);
        // NOTE: Enable this to invalidate the data after biometric change
        // paramsBuilder.setUserAuthenticationRequired(true);

        KeyGenParameterSpec keyGenParams = paramsBuilder.build();
        KeyGenerator keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE
        );
        keyGenerator.init(keyGenParams);
        return keyGenerator.generateKey();
    }

    private static class EncryptedData {

        private byte[] ciphertext;
        private byte[] iv;

        public EncryptedData(byte[] ciphertext, byte[] iv) {
            this.ciphertext = ciphertext;
            this.iv = iv;
        }

        public byte[] getCiphertext() {
            return ciphertext;
        }

        public void setCiphertext(byte[] ciphertext) {
            this.ciphertext = ciphertext;
        }

        public byte[] getIv() {
            return iv;
        }

        public void setIv(byte[] iv) {
            this.iv = iv;
        }
    }
}
