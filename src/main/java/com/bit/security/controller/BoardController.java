package com.bit.security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/board/")
public class BoardController {
    @GetMapping("showAll")
    public String showAll() {
        return "boardController.showAll()";
    }
}
