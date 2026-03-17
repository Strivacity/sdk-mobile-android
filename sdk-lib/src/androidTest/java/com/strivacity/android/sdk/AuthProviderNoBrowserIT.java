package com.strivacity.android.sdk;

import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;

import android.content.Context;
import android.net.Uri;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.strivacity.android.sdk.testfilters.NoBrowserEnvironment;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import net.openid.appauth.AppAuthConfiguration;
import net.openid.appauth.AuthorizationService;
import net.openid.appauth.connectivity.ConnectionBuilder;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

@NoBrowserEnvironment
@RunWith(AndroidJUnit4.class)
public class AuthProviderNoBrowserIT {

    private static final int WIRE_MOCK_SERVER_PORT = 8091;
    private static final String STORE_NAME =
        "com.strivacity.android.sdk.AuthState";
    private static final String ISSUER_ID = "default";

    private CompletableFuture<Void> waitForAsync;

    private WireMockServer wireMockServer;

    private Context context;
    private AuthProvider authProvider;

    private AuthFlowException expectedAuthFlowException;
    private boolean sessionChangeCallbackFailureInvoked;

    // region setup
    @Before
    public void setUp()
        throws NoSuchFieldException, IllegalAccessException, IOException {
        wireMockServer =
            new WireMockServer(wireMockConfig().port(WIRE_MOCK_SERVER_PORT));
        wireMockServer.start();
        wireMockServer.stubFor(
            WireMock
                .get("/default/.well-known/openid-configuration")
                .atPriority(1)
                .willReturn(WireMock.okJson(getJSONResponse("well-known.json")))
        );

        context =
            InstrumentationRegistry.getInstrumentation().getTargetContext();
        context
            .getSharedPreferences(STORE_NAME, Context.MODE_PRIVATE)
            .edit()
            .remove(STORE_NAME)
            .apply();

        expectedAuthFlowException =
            AuthFlowException.browserIntentResolutionFailed(
                new Exception("No browser")
            );

        waitForAsync = new CompletableFuture<>();
        sessionChangeCallbackFailureInvoked = false;

        authProvider =
            AuthProvider.create(
                context,
                Uri.parse(
                    "http://localhost:" +
                    WIRE_MOCK_SERVER_PORT +
                    "/" +
                    ISSUER_ID
                ),
                "client_id",
                Uri.parse(
                    "com.strivacity.android.sdk.test://localhost:" +
                    WIRE_MOCK_SERVER_PORT +
                    "/" +
                    ISSUER_ID +
                    "/oauth2redirect"
                ),
                null,
                new FlowResponseCallback() {
                    @Override
                    public void success(
                        @Nullable String accessToken,
                        @Nullable Map<String, Object> claims
                    ) {}

                    @Override
                    public void failure(@NonNull AuthFlowException exception) {
                        sessionChangeCallbackFailureInvoked = true;
                        assertThat(exception, notNullValue());
                        assertThat(
                            exception.toString(),
                            equalTo(expectedAuthFlowException.toString())
                        );
                        waitForAsync.complete(null);
                    }
                }
            );

        AppAuthConfiguration appAuthConfiguration = new AppAuthConfiguration.Builder()
            .setSkipIssuerHttpsCheck(true)
            .setConnectionBuilder(new TestConnectionBuilder())
            .build();
        AuthorizationService reflectedAuthService = new AuthorizationService(
            context,
            appAuthConfiguration
        );
        Field authServiceField = authProvider
            .getClass()
            .getDeclaredField("authService");
        authServiceField.setAccessible(true);
        authServiceField.set(authProvider, reflectedAuthService);

        Field defaultConnectionBuilderField = authProvider
            .getClass()
            .getDeclaredField("defaultConnectionBuilder");
        defaultConnectionBuilderField.setAccessible(true);
        defaultConnectionBuilderField.set(
            authProvider,
            new TestConnectionBuilder()
        );
    }

    @After
    public void tearDown() throws InterruptedException {
        wireMockServer.shutdown();
        Thread.sleep(1500); // wait some millis to shutdown the server
    }

    // endregion

    // region tests
    @Test
    @SuppressWarnings("ConstantConditions")
    public void startFlowFailsOnNoBrowser()
        throws ExecutionException, InterruptedException, TimeoutException {
        authProvider.startFlow(context, null);
        waitForAsync.get(10, TimeUnit.SECONDS);

        assertThat(sessionChangeCallbackFailureInvoked, equalTo(true));

        wireMockServer.verify(
            1,
            WireMock.getRequestedFor(
                WireMock.urlMatching(
                    "/default/.well-known/openid-configuration"
                )
            )
        );
    }

    // endregion

    // region helpers
    private static class TestConnectionBuilder implements ConnectionBuilder {

        private static final int CONNECTION_TIMEOUT_MS = (int) TimeUnit.SECONDS.toMillis(
            15
        );
        private static final int READ_TIMEOUT_MS = (int) TimeUnit.SECONDS.toMillis(
            10
        );

        @NonNull
        @Override
        public HttpURLConnection openConnection(@NonNull Uri uri)
            throws IOException {
            HttpURLConnection conn = (HttpURLConnection) new URL(uri.toString())
                .openConnection();
            conn.setConnectTimeout(CONNECTION_TIMEOUT_MS);
            conn.setReadTimeout(READ_TIMEOUT_MS);
            conn.setInstanceFollowRedirects(false);
            return conn;
        }
    }

    @SuppressWarnings("SameParameterValue")
    private static String getJSONResponse(String filename) throws IOException {
        return TestUtils.getJSONResponse(filename);
    }
    // endregion
}
