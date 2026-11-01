package com.secureshare.service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/** Dumb blob store for ENCRYPTED files. It never sees plaintext or keys. */
@Service
public class FileStorageService {

    private final Path root;

    public FileStorageService(@Value("${app.storage.path}") String storagePath) throws IOException {
        this.root = Paths.get(storagePath).toAbsolutePath().normalize();
        Files.createDirectories(root);
    }

    /** @return the generated blob name (e.g. 3f2a....enc), which is what File.storagePath holds. */
    public String store(byte[] blob) throws IOException {
        String name = UUID.randomUUID() + ".enc";
        Files.write(resolve(name), blob, StandardOpenOption.CREATE_NEW);
        return name;
    }

    public byte[] read(String name) throws IOException {
        return Files.readAllBytes(resolve(name));
    }

    public void deleteQuietly(String name) {
        try {
            Files.deleteIfExists(resolve(name));
        } catch (IOException | RuntimeException ignored) {
            // best effort clean-up
        }
    }

    private Path resolve(String name) {
        Path p = root.resolve(name).normalize();
        if (!p.startsWith(root)) {
            throw new IllegalArgumentException("Invalid storage path");   // path-traversal guard
        }
        return p;
    }
}
