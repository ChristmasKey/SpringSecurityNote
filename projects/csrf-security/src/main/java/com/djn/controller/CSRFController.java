package com.djn.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class CSRFController {

    @GetMapping("/toupdate")
    public String toUpdate() {
        return "csrf/csrf_test";
    }

    @PostMapping("/update_token")
    public String getToken() {
        return "csrf/csrf_token";
    }

}
