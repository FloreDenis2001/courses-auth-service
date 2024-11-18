package com.example.authservice.intercom.stripe.services;

import com.example.authservice.intercom.stripe.dto.PaymentDetailsDTO;
import com.stripe.Stripe;
import com.stripe.exception.StripeException;
import com.stripe.model.checkout.Session;
import com.stripe.param.checkout.SessionCreateParams;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class StripeService {

    @Value("${stripe.api.key}")
    private String stripeApiKey;

    public StripeService(@Value("${stripe.api.key}") String stripeApiKey) {
        this.stripeApiKey = stripeApiKey;
        Stripe.apiKey = stripeApiKey;
    }


    public String createCheckoutSession(String successUrl, String cancelUrl, List<PaymentDetailsDTO> orderSummary) throws StripeException {
        SessionCreateParams.Builder sessionBuilder = SessionCreateParams.builder()
                .setSuccessUrl(successUrl)
                .setCancelUrl(cancelUrl)
                .setMode(SessionCreateParams.Mode.PAYMENT)
                .addPaymentMethodType(SessionCreateParams.PaymentMethodType.CARD);

        for (PaymentDetailsDTO item : orderSummary) {
            sessionBuilder.addLineItem(
                    SessionCreateParams.LineItem.builder()
                            .setQuantity(item.getQuantity())
                            .setPriceData(
                                    SessionCreateParams.LineItem.PriceData.builder()
                                            .setCurrency("ron")
                                            .setUnitAmount(item.getPrice() * 100L)
                                            .setProductData(
                                                    SessionCreateParams.LineItem.PriceData.ProductData.builder()
                                                            .setName(item.getName())
                                                            .build()
                                            )
                                            .build()
                            )
                            .build()
            );
        }

        SessionCreateParams params = sessionBuilder.build();
        Session session = Session.create(params);
        return session.getUrl();
    }


}
