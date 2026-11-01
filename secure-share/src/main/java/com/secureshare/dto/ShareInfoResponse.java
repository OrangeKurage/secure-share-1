package com.secureshare.dto;

import com.secureshare.model.SharePermission;
import com.secureshare.model.ShareStatus;
import java.time.Instant;

public record ShareInfoResponse(Long shareId, Long recipientId, String recipientEmail,
                                SharePermission permission, ShareStatus status,
                                Instant expiryDate, Instant shareDate) {}
