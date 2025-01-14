package com.bit.security.controller;

import com.bit.security.model.TokenDTO;
import com.bit.security.model.UserDTO;
import com.bit.security.service.AuthService;
import com.bit.security.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/user/")
public class UserController {
    @Autowired
    private UserService userService;
    @Autowired
    private AuthService authService;

    @PostMapping("auth")
    public ResponseEntity<Map<String, Object>> auth(UserDTO userDTO) {
        TokenDTO tokenDTO = authService.auth(userDTO);
        Map<String, Object> resultMap = new HashMap<>();
        resultMap.put("result", tokenDTO);

        return ResponseEntity.status(HttpStatus.OK).body(resultMap);
    }

    @PostMapping("register")
    public ResponseEntity<Map<String, Object>> register(UserDTO userDTO) {
        userDTO.setAuthorities(new ArrayList<>()); // UserDetails 권한 승인
        System.out.println("userDTO: " + userDTO);

        Map<String, Object> resultMap = new HashMap<>();

        if (!userService.validateUsername(userDTO)) {
            resultMap.put("message", "중복된 아이디입니다.");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(resultMap);
        }

        if (!userService.validateNickname(userDTO)) {
            resultMap.put("messgae", "중복된 닉네임입니다.");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(resultMap);
        }
        userService.register(userDTO);

        return ResponseEntity.status(HttpStatus.OK).body(resultMap);
    }

    @GetMapping("arrive")
    public ResponseEntity<String> arrive() {
        return ResponseEntity.status(HttpStatus.OK).body("Arrived!");
    }
}
