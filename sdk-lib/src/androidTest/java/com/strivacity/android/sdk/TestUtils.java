package com.strivacity.android.sdk;

import androidx.test.platform.app.InstrumentationRegistry;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

class TestUtils {

    private TestUtils() {}

    static String getJSONResponse(String filename) throws IOException {
        try (
            final InputStream is = InstrumentationRegistry
                .getInstrumentation()
                .getContext()
                .getAssets()
                .open(filename)
        ) {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            byte[] chunk = new byte[4096];
            int bytesRead;
            while ((bytesRead = is.read(chunk)) != -1) {
                buffer.write(chunk, 0, bytesRead);
            }
            return buffer.toString();
        }
    }
}
