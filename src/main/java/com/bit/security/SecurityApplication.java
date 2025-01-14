package com.bit.security;

import org.apache.ibatis.session.SqlSession;
import org.apache.ibatis.session.SqlSessionFactory;
import org.mybatis.spring.SqlSessionFactoryBean;
import org.mybatis.spring.SqlSessionTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import javax.sql.DataSource;

@SpringBootApplication
public class SecurityApplication {
	public static void main(String[] args) {

		SpringApplication.run(SecurityApplication.class, args);
	}

	@Bean // Spring한테 특정 클래스 객체 생성/소멸 시키기
	public SqlSessionFactory sqlSesstionFactory(DataSource dataSource) throws Exception {
		SqlSessionFactoryBean sqlSessionFactoryBean = new SqlSessionFactoryBean();
		sqlSessionFactoryBean.setDataSource(dataSource); // DB 연결에 필요한 정보 로딩
		// mybatis 설정 파일 로딩
		sqlSessionFactoryBean.setConfigLocation(new ClassPathResource("mybatis/config.xml"));
		Resource[] resources = new PathMatchingResourcePatternResolver().getResources("classpath:/mybatis/mappers/*.xml");
		sqlSessionFactoryBean.setMapperLocations(resources);

		return sqlSessionFactoryBean.getObject();
	}

	@Bean
	public SqlSession sqlSession(SqlSessionFactory sqlSessionFactory) {
		return new SqlSessionTemplate(sqlSessionFactory);
	}

	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

}
