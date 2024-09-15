package com.example.authservice.intercom.b2;


import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

@RestController
@CrossOrigin
@RequestMapping("/server/api/v1/cloud/b2/")
public class B2S3Controller {

    private final B2S3Client b2S3Service;

    @Autowired
    public B2S3Controller(B2S3Client b2S3Service) {
        this.b2S3Service = b2S3Service;
    }

    @PostMapping("/upload")
    public ResponseEntity<String> uploadFile(@RequestParam("file") MultipartFile file, @RequestParam("fileName") String fileName) {
        try {
            String fileUrl = b2S3Service.uploadFile(file, fileName);
            return ResponseEntity.ok(fileUrl);
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error while uploading file");
        }
    }






}
