package com.cos.security1.config.oauth;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.config.auth.PrincipalDetailsService;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    private BCryptPasswordEncoder bCryptPasswordEncoder;

    public PrincipalOauth2UserService() {
        this.bCryptPasswordEncoder = new BCryptPasswordEncoder();
    }

    @Autowired
    private UserRepository userRepository;

    // 구글로 받은 userRequest 데이터에 대한 후처리되는 함수
    // 함수 종료시 @AtuhenticationPrincipal 어노테이션이 만들어진다.
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        log.info("userRequest.getClientRegistration={}", userRequest.getClientRegistration());
        log.info("userRequest.getAccessToken()={}", userRequest.getAccessToken().getTokenValue());

        OAuth2User oAuth2User = super.loadUser(userRequest);

        // 구글로그인 버튼 클릭 -> 구글로그인창 -> 로그인 완료 -> code리턴(OAuth2 - Client라이브러리) -> AccessToken요청
        // userRequest 정보 -> loaduser함수 호출 -> 구글로부터 회원프로필 받아줌
        log.info("oAuth2User.getAttributes()={}", oAuth2User.getAttributes());

        String provider = userRequest.getClientRegistration().getClientId(); // google
        String providerId = String.valueOf(oAuth2User.getAttributes().get("sub"));
        String username = provider + "_" + providerId;
        String password = bCryptPasswordEncoder.encode("겟인데어");
        String email = String.valueOf(oAuth2User.getAttributes().get("email"));
        String role = "ROLE_USER";

        User user = userRepository.findByUsername(username);

        if (user == null) {
            log.info("구글 로그인이 최초입니다.");
            user = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            userRepository.save(user);
        } else {
            log.info("구글 로그인을 이미 하였습니다.");
        }


        return new PrincipalDetails(user, oAuth2User.getAttributes());
    }
}
