package com.example.authservice.intercom.stripe.dto;

import java.util.List;

public record PaymentRequest(PaymentInfoData paymentInfoData, List<PaymentDetailsDTO>  paymentDetailsDTO) {
}
