package com.bit.security.provider;

import com.bit.security.model.TokenDTO;
import com.bit.security.model.UserDTO;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.security.Key;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

// 컴포넌트 어노테이션은 컨트롤러나 서비스는 아니지만 Springㅇ 따로 관리하는 클래스 객체에 붙이 됨(Bean과 비슷)
// 차이점은 Bean의 경우, Spring이 제공해주는 클래스들이나 외부 라이브러리 클래스를 불러오라는 뜻이 되고
// 컴포넌트는 우리가 직접 만든 클래스를 등록한는 차이.
@Component
public class JwtProvider {
    private Key key;

    public JwtProvider(@Value("${jwt.secret}") String secret) {
        byte[] bytes = Decoders.BASE64.decode(secret);
        this.key = Keys.hmacShaKeyFor(bytes);
    }

    // JWT 생성하기
    public TokenDTO generate(UserDTO userDTO) {
        TokenDTO tokenDTO = new TokenDTO();

        String authorities = userDTO.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining("."));

        // JWT에 포함될 정보들(회원번호와 닉네임)
        Long userId = (long) userDTO.getId();
        String nickname = userDTO.getNickname();
        // JWT에 포함될 만료일 계산
        long now = new Date().getTime();
        Date expDate = new Date(now + 86400 * 1000 * 10);

        String token = Jwts.builder()
                .claim("username", userDTO.getUsername())
                .claim("userId", userId)
                .claim("nickname", nickname)
                .claim("authorities", authorities)
                .setExpiration(expDate)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        tokenDTO.setType("Bearer");
        tokenDTO.setValue(token);

        return tokenDTO;

    }
    // JWT 안에서 claim 정보를 추출하는 메소드
    private Claims getClaims(String token) {
        try {
            // 실행 코드
            return Jwts.parser().setSigningKey(key).build().parseClaimsJws(token).getBody();
        } catch(ExpiredJwtException e) {
            // 위의 코드를 실행할 때 예외가 발생했을 때 어떤 처리를 할지 지정
            return e.getClaims();
        }
    }

    public String getUsernmae(String token) {
        return getClaims(token).get("username", String.class);
    }

    // JWT 복호화
    public Authentication getAuthentication(String token) {
        Claims claims = getClaims(token);

        if (claims.get("authorities") == null) {
            throw new RuntimeException("No Authorities Info included");
        }
        // aaa.bbb.ccc.ddd. ... 끝
        // aaa
        // bbb
        // ccc
        // ...
        // 끝
        Collection<? extends GrantedAuthority> authrities =
                Arrays.stream(claims
                                .get("authorities")
                                .toString() // 데이터를 문자열로 자름
                                .split("\\."))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList()
                        );
        UserDTO userDTO = new UserDTO();

        Collection<GrantedAuthority> authoList = new ArrayList<>();
        for (GrantedAuthority a : authrities) {
            SimpleGrantedAuthority authority = new SimpleGrantedAuthority(a.getAuthority());
            authoList.add(authority);
        }
        userDTO.setAuthorities(authoList);
        userDTO.setUsername(claims.getSubject());
        userDTO.setNickname((String)claims.get("nickname"));
        userDTO.setId((Integer)claims.get("userId"));


        return new UsernamePasswordAuthenticationToken(userDTO, "", authrities);
    }

    public boolean validate(String token) {
        try {
            Jwts.parser().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    public String readToken(HttpServletRequest request) {
        String token = request.getHeader("Authorization");
        if (StringUtils.hasText(token) && token.startsWith("Bearer")) {
            return token.substring(7);
        }

        return null;
    }

}
