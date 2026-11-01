package com.secureshare.cli;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

/** Minimal multipart/form-data builder (the JDK HttpClient has none). */
public final class MultipartBody {

    private final String boundary = "----SecureShare" + UUID.randomUUID().toString().replace("-", "");
    private final ByteArrayOutputStream out = new ByteArrayOutputStream();
    private boolean built;

    public String contentType() {
        return "multipart/form-data; boundary=" + boundary;
    }

    public MultipartBody text(String name, String value) {
        write("--" + boundary + "\r\n"
                + "Content-Disposition: form-data; name=\"" + clean(name) + "\"\r\n\r\n");
        write(value);
        write("\r\n");
        return this;
    }

    public MultipartBody file(String name, String filename, byte[] data) {
        write("--" + boundary + "\r\n"
                + "Content-Disposition: form-data; name=\"" + clean(name) + "\"; filename=\"" + clean(filename) + "\"\r\n"
                + "Content-Type: application/octet-stream\r\n\r\n");
        out.writeBytes(data);
        write("\r\n");
        return this;
    }

    public byte[] build() {
        if (!built) {
            write("--" + boundary + "--\r\n");
            built = true;
        }
        return out.toByteArray();
    }

    private void write(String s) {
        out.writeBytes(s.getBytes(StandardCharsets.UTF_8));
    }

    private static String clean(String s) {
        return s.replace("\"", "'").replace("\r", "").replace("\n", "");   // header-injection guard
    }
}
