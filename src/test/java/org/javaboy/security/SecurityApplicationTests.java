package org.javaboy.security;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import javax.lang.model.element.VariableElement;

@SpringBootTest
class SecurityApplicationTests {

    @Test
    void contextLoads() {

        for (int i = 0; i < 10; i++) {
            String encode = new BCryptPasswordEncoder().encode("123");
            System.out.println(encode);
        }
    }

}
