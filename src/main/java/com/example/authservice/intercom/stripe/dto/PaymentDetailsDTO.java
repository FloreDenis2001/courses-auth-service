package com.example.authservice.intercom.stripe.dto;

import lombok.*;

@Data
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class PaymentDetailsDTO {
    private String name;
    private int price;
    private String currency;
    private Long quantity;
}
