package com.example.authservice.intercom.b2;

import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.model.PutObjectRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;

@Service
public class B2S3Service {

    private final AmazonS3 s3Client;

    @Value("${b2.bucketName}")
    private String bucketName;

    public B2S3Service(AmazonS3 s3Client) {
        this.s3Client = s3Client;
    }

    public String uploadFile(File file, String fileName) {
        s3Client.putObject(new PutObjectRequest(bucketName, fileName, file));
        return s3Client.getUrl(bucketName, fileName).toString();
    }
}
