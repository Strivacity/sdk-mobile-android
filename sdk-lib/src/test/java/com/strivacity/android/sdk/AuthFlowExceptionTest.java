package com.strivacity.android.sdk;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class AuthFlowExceptionTest {

    @Test
    public void unexpected() {
        AuthFlowException authFlowException = AuthFlowException.UNEXPECTED;
        assertThat(authFlowException.getError(), is("Unexpected error"));
        assertThat(
            authFlowException.getErrorDescription(),
            is("An unexpected error happened")
        );
        assertThat(
            authFlowException.toString(),
            is("Unexpected error - An unexpected error happened")
        );
    }

    @Test
    public void unsupportedAuthenticationMethod() {
        AuthFlowException authFlowException = AuthFlowException.unsupportedAuthenticationMethod(
            "methodName",
            null
        );
        assertThat(
            authFlowException.getError(),
            is("Unsupported authentication method")
        );
        assertThat(authFlowException.getErrorDescription(), is("methodName"));
        assertThat(
            authFlowException.toString(),
            is("Unsupported authentication method - methodName")
        );
    }

    @Test
    public void ofWithoutRootCause() {
        AuthFlowException authFlowException = AuthFlowException.of(
            "error",
            "error description",
            null
        );
        assertThat(authFlowException.getError(), is("error"));
        assertThat(
            authFlowException.getErrorDescription(),
            is("error description")
        );
        assertThat(
            authFlowException.toString(),
            is("error - error description")
        );
    }

    @Test
    public void ofWithRootCauseAndErrorWithDescription() {
        Exception rootCause = new Exception("exception");
        AuthFlowException authFlowException = AuthFlowException.of(
            "error",
            "error description",
            rootCause
        );
        assertThat(authFlowException.getError(), is("error"));
        assertThat(
            authFlowException.getErrorDescription(),
            is("error description")
        );
        assertThat(
            authFlowException.toString(),
            is("error - error description")
        );
        assertThat(authFlowException.getCause().getMessage(), is("exception"));
    }

    @Test
    public void ofWithRootCauseWithoutErrorAndDescription() {
        Exception rootCause = new Exception("exception");
        AuthFlowException authFlowException = AuthFlowException.of(
            null,
            null,
            rootCause
        );
        assertThat(authFlowException.getError(), is(nullValue()));
        assertThat(authFlowException.getErrorDescription(), is("exception"));
        assertThat(authFlowException.toString(), is("null - exception"));
        assertThat(authFlowException.getCause().getMessage(), is("exception"));
    }

    @Test
    public void ofWithRootCauseWithErrorAndWithoutDescription() {
        Exception rootCause = new Exception("exception");
        AuthFlowException authFlowException = AuthFlowException.of(
            "error",
            null,
            rootCause
        );
        assertThat(authFlowException.getError(), is("error"));
        assertThat(authFlowException.getErrorDescription(), is(nullValue()));
        assertThat(authFlowException.toString(), is("error - null"));
        assertThat(authFlowException.getCause().getMessage(), is("exception"));
    }

    @Test
    public void ofWithRootCauseWithoutErrorAndWithDescription() {
        Exception rootCause = new Exception("exception");
        AuthFlowException authFlowException = AuthFlowException.of(
            null,
            "description",
            rootCause
        );
        assertThat(authFlowException.getError(), is(nullValue()));
        assertThat(authFlowException.getErrorDescription(), is("description"));
        assertThat(authFlowException.toString(), is("null - description"));
        assertThat(authFlowException.getCause().getMessage(), is("exception"));
    }
}
