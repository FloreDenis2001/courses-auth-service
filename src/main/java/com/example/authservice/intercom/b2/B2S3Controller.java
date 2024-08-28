package com.example.authservice.intercom.b2;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/files")
public class B2S3Controller {

    private final B2S3Service b2S3Service;

    @Autowired
    public B2S3Controller(B2S3Service b2S3Service) {
        this.b2S3Service = b2S3Service;
    }

    @PostMapping("/upload")
    public ResponseEntity<String> uploadFile(@RequestParam("file") MultipartFile file) {
        // Validate file
        if (file.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("File is empty.");
        }

        Path tempFilePath = null;
        try {
            // Convert MultipartFile to File
            tempFilePath = convertMultiPartToFile(file);

            // Generate a unique filename
            String fileName = UUID.randomUUID() + "_" + file.getOriginalFilename();

            // Upload the file and get the URL
            String fileUrl = b2S3Service.uploadFile(tempFilePath.toFile(), fileName);

            return ResponseEntity.ok(fileUrl);
        } catch (IOException e) {
            // Handle exception
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to upload file.");
        } finally {
            // Delete the temporary file
            if (tempFilePath != null) {
                try {
                    Files.deleteIfExists(tempFilePath);
                } catch (IOException e) {
                    System.err.println("Failed to delete temporary file: " + e.getMessage());
                }
            }
        }
    }

    private Path convertMultiPartToFile(MultipartFile file) throws IOException {
        // Create a temporary file with unique name
        Path tempFilePath = Files.createTempFile(UUID.randomUUID().toString(), "." + getFileExtension(file.getOriginalFilename()));
        try (FileOutputStream fos = new FileOutputStream(tempFilePath.toFile())) {
            fos.write(file.getBytes());
        }
        return tempFilePath;
    }

    private String getFileExtension(String filename) {
        String[] parts = filename.split("\\.");
        return parts.length > 1 ? parts[parts.length - 1] : "";
    }
}
