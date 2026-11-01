package com.secureshare;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class HealthEndpointTest {

    @Autowired
    private MockMvc mvc;

    @Test
    void healthReturnsOk() throws Exception {
        mvc.perform(get("/health"))
           .andExpect(status().isOk())
           .andExpect(jsonPath("$.status").value("ok"));
    }

    @Test
    void webUiIsPublic_andFileApiStaysProtected() throws Exception {
        mvc.perform(get("/index.html"))
           .andExpect(status().isOk())
           .andExpect(content().string(containsString("encrypted")));
        mvc.perform(get("/app.js"))
           .andExpect(status().isOk())
           .andExpect(content().string(containsString("Integrity verified")));
        mvc.perform(get("/files/mine")).andExpect(status().isUnauthorized());
    }
}
