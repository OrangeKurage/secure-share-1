package com.secureshare.dto;

/** What the client reports after trying to open a file (names fit the 20-char audit status column). */
public enum ReceiptOutcome { SUCCESS, FAILURE_INTEGRITY, FAILURE_SIGNATURE, FAILURE_KEY }
