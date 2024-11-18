package com.example.authservice.intercom.stripe.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

public record PaymentInfoData(String name,String phone,String email,String city,String country,String address) {
}
