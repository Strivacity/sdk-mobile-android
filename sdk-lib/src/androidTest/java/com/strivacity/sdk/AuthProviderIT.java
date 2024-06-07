package com.strivacity.android.sdk;

import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

import android.content.Context;
import android.net.Uri;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.common.FileSource;
import com.github.tomakehurst.wiremock.extension.Parameters;
import com.github.tomakehurst.wiremock.extension.ResponseTransformer;
import com.github.tomakehurst.wiremock.http.Request;
import com.github.tomakehurst.wiremock.http.Response;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import org.json.JSONObject;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import net.openid.appauth.AppAuthConfiguration;
import net.openid.appauth.AuthorizationService;
import net.openid.appauth.connectivity.ConnectionBuilder;

import no.nav.security.mock.oauth2.MockOAuth2Server;
import no.nav.security.mock.oauth2.token.DefaultOAuth2TokenCallback;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

@RunWith(AndroidJUnit4.class)
public class AuthProviderIT {

    private static final int MOCK_OAUTH2_SERVER_PORT = 8090;
    private static final int WIRE_MOCK_SERVER_PORT = 8091;
    private static final String STORE_NAME =
        "com.strivacity.android.sdk.AuthState";
    private static final String ISSUER_ID = "default";
    private static final long TOKEN_EXPIRY = 3600;

    private CompletableFuture<Void> waitForAsync;

    private MockOAuth2Server mockOAuth2Server;
    private WireMockServer wireMockServer;

    private Context context;
    private AuthProvider authProvider;
    private FlowResponseCallback flowResponseCallback;
    private EndSessionCallback endSessionCallback;

    private AuthFlowException expectedAuthFlowException;
    private Map<String, Object> expectedClaims;
    private boolean endSessionCalled;

    // region setup
    @Before
    public void setUp()
        throws NoSuchFieldException, IllegalAccessException, IOException {
        mockOAuth2Server = new MockOAuth2Server();
        mockOAuth2Server.start(MOCK_OAUTH2_SERVER_PORT);

        ResponseTransformer responseTransformer = new ResponseTransformer() {
            @Override
            public Response transform(
                Request request,
                Response response,
                FileSource files,
                Parameters parameters
            ) {
                String responseBody = response.getBodyAsString();
                try {
                    JSONObject responseBodyAsJSON = new JSONObject(
                        responseBody
                    );
                    String rawIdToken = responseBodyAsJSON.getString(
                        "id_token"
                    );

                    SignedJWT signedJWT = SignedJWT.parse(rawIdToken);
                    Map<String, Object> payload = signedJWT
                        .getPayload()
                        .toJSONObject();
                    payload.put(
                        "iss",
                        "http://localhost:" +
                        WIRE_MOCK_SERVER_PORT +
                        "/" +
                        ISSUER_ID
                    );

                    RSAKey rsaJWK = new RSAKeyGenerator(2048)
                        .keyID("default")
                        .generate();
                    JWSSigner signer = new RSASSASigner(rsaJWK);
                    JWTClaimsSet claimsSet = JWTClaimsSet.parse(payload);
                    SignedJWT newSignedJWT = new SignedJWT(
                        new JWSHeader.Builder(JWSAlgorithm.RS256)
                            .keyID(rsaJWK.getKeyID())
                            .build(),
                        claimsSet
                    );
                    newSignedJWT.sign(signer);

                    String newRawIdToken = newSignedJWT.serialize();
                    responseBodyAsJSON.put("id_token", newRawIdToken);

                    responseBody = responseBodyAsJSON.toString();
                } catch (Exception ignored) {}
                return Response.Builder
                    .like(response)
                    .but()
                    .body(responseBody)
                    .build();
            }

            @Override
            public String getName() {
                return "issuer-port-replacer";
            }
        };

        wireMockServer =
            new WireMockServer(
                wireMockConfig()
                    .port(WIRE_MOCK_SERVER_PORT)
                    .extensions(responseTransformer)
            );
        wireMockServer.start();
        wireMockServer.stubFor(
            WireMock
                .get("/default/.well-known/openid-configuration")
                .atPriority(1)
                .willReturn(WireMock.okJson(getJSONResponse("well-known.json")))
        );
        wireMockServer.stubFor(
            WireMock
                .post("default/token")
                .atPriority(1)
                .willReturn(
                    WireMock
                        .aResponse()
                        .proxiedFrom(
                            "http://localhost:" + MOCK_OAUTH2_SERVER_PORT
                        )
                        .withTransformers("issuer-port-replacer")
                )
        );
        wireMockServer.stubFor(
            WireMock
                .any(WireMock.anyUrl())
                .atPriority(2)
                .willReturn(
                    WireMock
                        .aResponse()
                        .proxiedFrom(
                            "http://localhost:" + MOCK_OAUTH2_SERVER_PORT
                        )
                )
        );

        context =
            InstrumentationRegistry.getInstrumentation().getTargetContext();
        context
            .getSharedPreferences(STORE_NAME, Context.MODE_PRIVATE)
            .edit()
            .remove(STORE_NAME)
            .apply();

        authProvider =
            AuthProvider
                .create(
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
                    null
                )
                .withScopes("scope1", "scope2")
                .withLoginHint("login_hint")
                .withAcrValues("acr1 acr2")
                .withUiLocales("hu-HU fi-FI")
                .withPostLogoutUri(
                    Uri.parse(
                        "com.strivacity.android.sdk.test://localhost:" +
                        WIRE_MOCK_SERVER_PORT +
                        "/" +
                        ISSUER_ID +
                        "/oauth2PostLogoutRedirect"
                    )
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

        Field defaultConfigurationBuilderField = authProvider
            .getClass()
            .getDeclaredField("defaultConnectionBuilder");
        defaultConfigurationBuilderField.setAccessible(true);
        defaultConfigurationBuilderField.set(
            authProvider,
            new TestConnectionBuilder()
        );

        expectedAuthFlowException = null;
        expectedClaims = Map.of("key1", "value1", "key2", "value2");

        waitForAsync = new CompletableFuture<>();

        flowResponseCallback =
            new FlowResponseCallback() {
                @Override
                public void success(
                    @Nullable String accessToken,
                    @Nullable Map<String, Object> claims
                ) {
                    assertThat(expectedAuthFlowException, is(nullValue())); // NOTE: check if success is not called when we expect failure method calls

                    assertThat(accessToken, is(notNullValue()));

                    if (expectedClaims == null) {
                        assertThat(claims, is(nullValue()));
                    } else {
                        assertThat(claims, is(notNullValue()));
                        expectedClaims.forEach((key, value) -> {
                            assertThat(claims, hasKey(key));
                            assertThat(claims.get(key), equalTo(value));
                        });
                    }

                    waitForAsync.complete(null);
                }

                @Override
                public void failure(@NonNull AuthFlowException exception) {
                    assertThat(expectedAuthFlowException, is(notNullValue())); // NOTE: check if failure is not called when we expect success method calls

                    assertThat(
                        exception.toString(),
                        equalTo(expectedAuthFlowException.toString())
                    );
                    waitForAsync.complete(null);
                }
            };

        endSessionCalled = false;

        endSessionCallback =
            () -> {
                endSessionCalled = true;
                waitForAsync.complete(null);
            };
    }

    @After
    public void tearDown() throws InterruptedException {
        wireMockServer.shutdown();
        mockOAuth2Server.shutdown();
        Thread.sleep(1500); // wait some millis to shutdown the server
    }

    // endregion

    // region tests
    @Test
    public void startFlowSuccess()
        throws ExecutionException, InterruptedException, TimeoutException {
        enqueueCallback(TOKEN_EXPIRY);
        authProvider.startFlow(context, flowResponseCallback);
        waitForAsync.get(10, TimeUnit.SECONDS);

        verifyWellKnown(1);
        verifyAuthorize(1);
        verifyTokenExchange(1);
        verifyRefreshToken(0);
        verifyLogoutUrl(0);
    }

    @Test
    public void startFlowConfigurationError()
        throws NoSuchFieldException, IllegalAccessException, ExecutionException, InterruptedException, TimeoutException {
        expectedAuthFlowException =
            AuthFlowException.of(null, "Network error", null);

        Field issuerField = authProvider.getClass().getDeclaredField("issuer");
        issuerField.setAccessible(true);
        issuerField.set(authProvider, Uri.parse("http://" + UUID.randomUUID()));

        enqueueCallback(TOKEN_EXPIRY);
        authProvider.startFlow(context, flowResponseCallback);
        waitForAsync.get(10, TimeUnit.SECONDS);

        verifyWellKnown(0);
        verifyAuthorize(0);
        verifyTokenExchange(0);
        verifyRefreshToken(0);
        verifyLogoutUrl(0);
    }

    @Test
    public void startFlowStateAuthenticated()
        throws ExecutionException, InterruptedException, TimeoutException {
        enqueueCallback(TOKEN_EXPIRY);
        authProvider.startFlow(context, flowResponseCallback);
        waitForAsync.get(10, TimeUnit.SECONDS);

        verifyWellKnown(1);
        verifyAuthorize(1);
        verifyTokenExchange(1);
        verifyRefreshToken(0);
        verifyLogoutUrl(0);

        waitForAsync = new CompletableFuture<>();
        authProvider.startFlow(context, flowResponseCallback);
        waitForAsync.get(10, TimeUnit.SECONDS);

        verifyWellKnown(2);
        verifyAuthorize(1);
        verifyTokenExchange(1);
        verifyRefreshToken(0);
        verifyLogoutUrl(0);
    }

    @Test
    public void getAccessTokenSuccess()
        throws ExecutionException, InterruptedException, TimeoutException {
        enqueueCallback(TOKEN_EXPIRY);
        authProvider.startFlow(context, flowResponseCallback);
        waitForAsync.get(10, TimeUnit.SECONDS);

        verifyWellKnown(1);
        verifyAuthorize(1);
        verifyTokenExchange(1);
        verifyRefreshToken(0);
        verifyLogoutUrl(0);

        waitForAsync = new CompletableFuture<>();
        authProvider.getAccessToken(flowResponseCallback);
        waitForAsync.get(10, TimeUnit.SECONDS);

        verifyWellKnown(1);
        verifyAuthorize(1);
        verifyTokenExchange(1);
        verifyRefreshToken(0);
        verifyLogoutUrl(0);
    }

    @Test
    public void getAccessTokenUsingRefreshToken()
        throws InterruptedException, ExecutionException, TimeoutException {
        enqueueCallback(1);
        authProvider.startFlow(context, flowResponseCallback);
        waitForAsync.get(10, TimeUnit.SECONDS);

        verifyWellKnown(1);
        verifyAuthorize(1);
        verifyTokenExchange(1);
        verifyRefreshToken(0);
        verifyLogoutUrl(0);

        Thread.sleep(2000); // wait for token expiry

        waitForAsync = new CompletableFuture<>();
        authProvider.getAccessToken(flowResponseCallback);
        waitForAsync.get(10, TimeUnit.SECONDS);

        verifyWellKnown(1);
        verifyAuthorize(1);
        verifyTokenExchange(1);
        verifyRefreshToken(1);
        verifyLogoutUrl(0);
    }

    @Test
    public void getAccessTokenReturnsException()
        throws ExecutionException, InterruptedException, TimeoutException {
        enqueueCallback(TOKEN_EXPIRY);
        expectedAuthFlowException =
            AuthFlowException.of(
                null,
                "No refresh token available and token have expired",
                null
            );
        authProvider.getAccessToken(flowResponseCallback);
        waitForAsync.get(10, TimeUnit.SECONDS);

        verifyWellKnown(0);
        verifyAuthorize(0);
        verifyTokenExchange(0);
        verifyRefreshToken(0);
        verifyLogoutUrl(0);
    }

    @Test
    public void getLastRetrievedClaimsSuccess()
        throws ExecutionException, InterruptedException, TimeoutException {
        enqueueCallback(TOKEN_EXPIRY);
        authProvider.startFlow(context, flowResponseCallback);
        waitForAsync.get(10, TimeUnit.SECONDS);

        verifyWellKnown(1);
        verifyAuthorize(1);
        verifyTokenExchange(1);
        verifyRefreshToken(0);
        verifyLogoutUrl(0);

        Map<String, Object> claims = authProvider.getLastRetrievedClaims();
        assertThat(claims, is(notNullValue()));
        expectedClaims.forEach((s, o) -> assertThat(claims.get(s), equalTo(o)));

        verifyWellKnown(1);
        verifyAuthorize(1);
        verifyTokenExchange(1);
        verifyRefreshToken(0);
        verifyLogoutUrl(0);
    }

    @Test
    public void getLastRetrievedClaimsNull() {
        enqueueCallback(TOKEN_EXPIRY);
        Map<String, Object> claims = authProvider.getLastRetrievedClaims();
        assertThat(claims, is(nullValue()));

        verifyWellKnown(0);
        verifyAuthorize(0);
        verifyTokenExchange(0);
        verifyRefreshToken(0);
        verifyLogoutUrl(0);
    }

    @Test
    public void logoutSuccess()
        throws ExecutionException, InterruptedException, TimeoutException {
        enqueueCallback(TOKEN_EXPIRY);
        authProvider.startFlow(context, flowResponseCallback);
        waitForAsync.get(10, TimeUnit.SECONDS);

        verifyWellKnown(1);
        verifyAuthorize(1);
        verifyTokenExchange(1);
        verifyRefreshToken(0);
        verifyLogoutUrl(0);

        waitForAsync = new CompletableFuture<>();
        authProvider.logout(context, endSessionCallback);
        waitForAsync.get(10, TimeUnit.SECONDS);
        assertThat(endSessionCalled, is(true));

        verifyWellKnown(1);
        verifyAuthorize(1);
        verifyTokenExchange(1);
        verifyRefreshToken(0);
        verifyLogoutUrl(1);

        enqueueCallback(TOKEN_EXPIRY);
        waitForAsync = new CompletableFuture<>();
        authProvider.startFlow(context, flowResponseCallback);
        waitForAsync.get(10, TimeUnit.SECONDS);

        verifyWellKnown(2);
        verifyAuthorize(2);
        verifyTokenExchange(2);
        verifyRefreshToken(0);
        verifyLogoutUrl(1);
    }

    @Test
    public void logoutNotAuthenticatedState()
        throws ExecutionException, InterruptedException, TimeoutException {
        enqueueCallback(TOKEN_EXPIRY);
        authProvider.logout(context, endSessionCallback);
        waitForAsync.get(10, TimeUnit.SECONDS);
        assertThat(endSessionCalled, is(true));

        verifyWellKnown(0);
        verifyAuthorize(0);
        verifyTokenExchange(0);
        verifyRefreshToken(0);
        verifyLogoutUrl(0);
    }

    @Test
    public void checkAuthenticatedWithAuthenticatedState()
        throws ExecutionException, InterruptedException, TimeoutException {
        enqueueCallback(TOKEN_EXPIRY);
        authProvider.startFlow(context, flowResponseCallback);
        waitForAsync.get(10, TimeUnit.SECONDS);

        verifyWellKnown(1);
        verifyAuthorize(1);
        verifyTokenExchange(1);
        verifyRefreshToken(0);
        verifyLogoutUrl(0);

        waitForAsync = new CompletableFuture<>();
        authProvider.checkAuthenticated(aBoolean -> {
            assertThat(aBoolean, is(true));
            waitForAsync.complete(null);
        });
        waitForAsync.get(10, TimeUnit.SECONDS);

        verifyWellKnown(1);
        verifyAuthorize(1);
        verifyTokenExchange(1);
        verifyRefreshToken(0);
        verifyLogoutUrl(0);
    }

    @Test
    public void checkAuthenticatedUsingRefreshToken()
        throws InterruptedException, ExecutionException, TimeoutException {
        enqueueCallback(1);
        authProvider.startFlow(context, flowResponseCallback);
        waitForAsync.get(10, TimeUnit.SECONDS);

        verifyWellKnown(1);
        verifyAuthorize(1);
        verifyTokenExchange(1);
        verifyRefreshToken(0);
        verifyLogoutUrl(0);

        Thread.sleep(2000); // wait for token expiry

        waitForAsync = new CompletableFuture<>();
        authProvider.checkAuthenticated(aBoolean -> {
            assertThat(aBoolean, is(true));
            waitForAsync.complete(null);
        });
        waitForAsync.get(10, TimeUnit.SECONDS);

        verifyWellKnown(1);
        verifyAuthorize(1);
        verifyTokenExchange(1);
        verifyRefreshToken(1);
        verifyLogoutUrl(0);
    }

    @Test
    public void checkAuthenticatedWithoutAuthenticatedState()
        throws ExecutionException, InterruptedException, TimeoutException {
        authProvider.checkAuthenticated(aBoolean -> {
            assertThat(aBoolean, is(false));
            waitForAsync.complete(null);
        });
        waitForAsync.get(10, TimeUnit.SECONDS);

        verifyWellKnown(0);
        verifyAuthorize(0);
        verifyTokenExchange(0);
        verifyRefreshToken(0);
        verifyLogoutUrl(0);
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
        try (
            final InputStream is = InstrumentationRegistry
                .getInstrumentation()
                .getContext()
                .getAssets()
                .open(filename)
        ) {
            return new String(is.readAllBytes());
        }
    }

    private void enqueueCallback(long expiry) {
        mockOAuth2Server.enqueueCallback(
            new DefaultOAuth2TokenCallback(
                ISSUER_ID,
                UUID.randomUUID().toString(),
                JOSEObjectType.JWT.getType(),
                null,
                expectedClaims,
                expiry
            )
        );
    }

    private void verifyWellKnown(int count) {
        wireMockServer.verify(
            count,
            WireMock.getRequestedFor(
                WireMock.urlMatching(
                    "/default/.well-known/openid-configuration"
                )
            )
        );
    }

    private void verifyAuthorize(int count) {
        wireMockServer.verify(
            count,
            WireMock
                .getRequestedFor(WireMock.urlMatching("/default/authorize.*"))
                .withQueryParam("response_type", WireMock.matching("code"))
                .withQueryParam("login_hint", WireMock.matching("login_hint"))
                .withQueryParam("acr_values", WireMock.matching("acr1 acr2"))
                .withQueryParam("ui_locales", WireMock.matching("hu-HU fi-FI"))
                .withQueryParam("scope", WireMock.containing("offline"))
                .withQueryParam("scope", WireMock.containing("openid"))
                .withQueryParam("scope", WireMock.containing("scope1"))
                .withQueryParam("scope", WireMock.containing("scope2"))
                .withQueryParam(
                    "redirect_uri",
                    WireMock.matching(
                        "com.strivacity.android.sdk.test://localhost:8091/default/oauth2redirect"
                    )
                )
                .withQueryParam("client_id", WireMock.matching("client_id"))
                .withQueryParam("code_challenge", WireMock.matching(".*"))
                .withQueryParam(
                    "code_challenge_method",
                    WireMock.matching(".*")
                )
        );
    }

    private void verifyTokenExchange(int count) {
        wireMockServer.verify(
            count,
            WireMock
                .postRequestedFor(WireMock.urlMatching("/default/token"))
                .withRequestBody(
                    WireMock.containing("grant_type=authorization_code")
                )
        );
    }

    private void verifyRefreshToken(int count) {
        wireMockServer.verify(
            count,
            WireMock
                .postRequestedFor(WireMock.urlMatching("/default/token"))
                .withRequestBody(
                    WireMock.containing("grant_type=refresh_token")
                )
        );
    }

    private void verifyLogoutUrl(int count) {
        wireMockServer.verify(
            count,
            WireMock
                .getRequestedFor(WireMock.urlMatching("/default/endsession.*"))
                .withQueryParam(
                    "post_logout_redirect_uri",
                    WireMock.matching(
                        "com.strivacity.android.sdk.test://localhost:8091/default/oauth2PostLogoutRedirect"
                    )
                )
                .withQueryParam("id_token_hint", WireMock.matching(".+"))
        );
    }
    // endregion
}
