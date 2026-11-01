package com.secureshare.dto;

import com.secureshare.model.SharePermission;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import java.time.Instant;
import java.util.List;

/** permission defaults to DOWNLOAD; expiresAt is optional (null = never expires). */
public record ShareRequest(@NotEmpty @Valid List<ShareRecipient> recipients,
                           SharePermission permission,
                           Instant expiresAt) {}
