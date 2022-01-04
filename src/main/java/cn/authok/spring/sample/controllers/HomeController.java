package cn.authok.spring.sample.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/home")
public class HomeController {
    @GetMapping()
    public String index() {
        return "home";
    }

    @GetMapping("test")
    public String test() {
        return "test";
    }
}
