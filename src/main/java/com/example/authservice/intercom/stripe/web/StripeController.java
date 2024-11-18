package com.example.authservice.intercom.stripe.web;

import com.example.authservice.intercom.stripe.dto.PaymentRequest;
import com.example.authservice.intercom.stripe.services.StripeService;
import com.stripe.exception.StripeException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/server/api/v1/")
public class StripeController {

    private final StripeService stripeService;

    public StripeController(StripeService stripeService) {
        this.stripeService = stripeService;
    }

    @PostMapping("/create-checkout-session")
    public ResponseEntity<?> createCheckoutSession(@RequestBody PaymentRequest checkoutRequest) {
        try {
            String sessionUrl = stripeService.createCheckoutSession(
                    "https://example.com/success",
                    "https://example.com/cancel",
                    checkoutRequest.paymentDetailsDTO()
            );
            return ResponseEntity.ok(Map.of("url", sessionUrl));
        } catch (StripeException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("message", e.getMessage()));
        }
    }



    @GetMapping
    public String test() {
        return "Hello";
    }
}
