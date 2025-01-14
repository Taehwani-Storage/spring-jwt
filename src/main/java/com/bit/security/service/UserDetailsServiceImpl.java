package com.bit.security.service;

import com.bit.security.model.UserDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    @Autowired
    private UserService userService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 이 메소드는 사용자가 로그인 요청을 보내면 자동을 호출되고
        // 우리 DB에서 해당 유저네임을 가진 사용자를 불러와서
        // 로그인 정보가 정확한지 비교하여 일치하는 회원을 반환.
        UserDTO userDTO = userService.loadByUserName(username);

        System.out.println(userDTO);

        return userDTO;
    }

    public String login(UserDTO userDTO) {
        if(loadUserByUsername(userDTO.getUsername()) == null) {

        }

        String token = "";
        return token;
    }
}
