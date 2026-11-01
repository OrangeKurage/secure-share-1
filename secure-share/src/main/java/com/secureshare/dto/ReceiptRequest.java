package com.secureshare.dto;

import jakarta.validation.constraints.NotNull;

public record ReceiptRequest(@NotNull ReceiptOutcome outcome) {}
