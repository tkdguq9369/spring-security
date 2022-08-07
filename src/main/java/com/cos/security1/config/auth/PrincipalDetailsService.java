package com.cos.security1.config.auth;

import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// 시큐리티 설정에서 /login요청이 오면 UserDetailsService 타입으로 IoC 되어있는
// loaduserByUsername 메서드가 실행됨.
@Slf4j
@Service
public class PrincipalDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    //시큐리티 session ( Authentication(UserdDetails) )
    // 함수 종료시 @AtuhenticationPrincipal 어노테이션이 만들어진다.
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        log.info("username={}", username);

        User user = userRepository.findByUsername(username);

        if(user != null ){
            return new PrincipalDetails(user);
        }

        return null;
    }
}
