package com.secureshare.cli;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.UUID;

/** Thin wrapper over java.net.http.HttpClient for the REST API. Turns HTTP errors into CliException. */
public class ApiClient {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    private final String baseUrl;
    private final String token;

    public ApiClient(String baseUrl, String token) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.token = token;
    }

    public JsonNode get(String path) {
        return parse(send(request(path).GET().build()));
    }

    public byte[] getBytes(String path) {
        return send(request(path).GET().build()).body();
    }

    public JsonNode postJson(String path, Object body) {
        try {
            byte[] json = MAPPER.writeValueAsBytes(body);
            HttpRequest req = request(path)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(json)).build();
            return parse(send(req));
        } catch (JsonProcessingException e) {
            throw new CliException("Could not encode the request: " + e.getMessage());
        }
    }

    /** multipart/form-data with plain text fields plus one binary file part. */
    public JsonNode postMultipart(String path, Map<String, String> fields, String fileField, byte[] data) {
        String boundary = "----ShareCli" + UUID.randomUUID().toString().replace("-", "");
        ByteArrayOutputStream out = new ByteArrayOutputStream(data.length + 2048);
        for (Map.Entry<String, String> f : fields.entrySet()) {
            out.writeBytes(("--" + boundary + "\r\nContent-Disposition: form-data; name=\"" + f.getKey()
                    + "\"\r\n\r\n" + f.getValue() + "\r\n").getBytes(StandardCharsets.UTF_8));
        }
        out.writeBytes(("--" + boundary + "\r\nContent-Disposition: form-data; name=\"" + fileField
                + "\"; filename=\"blob.enc\"\r\nContent-Type: application/octet-stream\r\n\r\n")
                .getBytes(StandardCharsets.UTF_8));
        out.writeBytes(data);
        out.writeBytes(("\r\n--" + boundary + "--\r\n").getBytes(StandardCharsets.UTF_8));

        HttpRequest req = request(path)
                .header("Content-Type", "multipart/form-data; boundary=" + boundary)
                .POST(HttpRequest.BodyPublishers.ofByteArray(out.toByteArray())).build();
        return parse(send(req));
    }

    // ---------------------------------------------------------------- internals

    private HttpRequest.Builder request(String path) {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(baseUrl + path)).timeout(Duration.ofSeconds(120));
        if (token != null) b.header("Authorization", "Bearer " + token);
        return b;
    }

    private HttpResponse<byte[]> send(HttpRequest req) {
        try {
            HttpResponse<byte[]> r = http.send(req, HttpResponse.BodyHandlers.ofByteArray());
            if (r.statusCode() >= 400) throw error(r);
            return r;
        } catch (IOException e) {
            throw new CliException("Cannot reach the server at " + baseUrl + " (" + e.getMessage() + ")");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new CliException("Interrupted");
        }
    }

    private JsonNode parse(HttpResponse<byte[]> r) {
        byte[] b = r.body();
        if (b == null || b.length == 0) return MAPPER.nullNode();
        try {
            return MAPPER.readTree(b);
        } catch (IOException e) {
            throw new CliException("Unexpected (non-JSON) response from the server");
        }
    }

    private CliException error(HttpResponse<byte[]> r) {
        String msg = null;
        try {
            JsonNode n = MAPPER.readTree(r.body());
            if (n != null && n.hasNonNull("message")) msg = n.get("message").asText();
        } catch (IOException | RuntimeException ignored) {
            // body was empty or not JSON
        }
        if (msg == null) {
            msg = r.statusCode() == 401
                    ? "Not logged in, or the session expired. Run: share login --email <you@example.com>"
                    : "The server answered HTTP " + r.statusCode();
        }
        return new CliException(msg);
    }
}
