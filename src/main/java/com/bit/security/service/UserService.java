package com.bit.security.service;

import com.bit.security.model.UserDTO;
import org.apache.ibatis.session.SqlSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {
    @Autowired
    private BCryptPasswordEncoder encoder;

    @Autowired
    private SqlSession sqlSession;

    private final String NAMESPACE = "mappers.UserMapper";

    public UserDTO loadByUserName(String username) {

        return sqlSession.selectOne(NAMESPACE + ".selectByUsername", username);
    }

    public void register(UserDTO userDTO) {
        userDTO.setPassword(encoder.encode(userDTO.getPassword()));
        sqlSession.insert(NAMESPACE + ".register", userDTO);
    }

    public boolean validateUsername(UserDTO userDTO) {
        return sqlSession.selectOne(NAMESPACE + ".validateUsername", userDTO) == null;
    }

    public boolean validateNickname(UserDTO userDTO) {
        return sqlSession.selectOne(NAMESPACE + ".validateNickname", userDTO) == null;
    }
}
