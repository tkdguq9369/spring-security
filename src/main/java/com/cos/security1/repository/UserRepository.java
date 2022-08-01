package com.cos.security1.repository;

import com.cos.security1.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

// CRUD 함수를 JpaRepository에 있음.
// @repository가 없어도 IoC가 됨. JpaRepository를 상속했기 때문
public interface UserRepository extends JpaRepository<User, Integer> {

}
