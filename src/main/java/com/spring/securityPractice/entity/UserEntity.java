package com.spring.securityPractice.entity;

import java.util.List;

import com.spring.securityPractice.model.ResponseDto;

import jakarta.persistence.*;
import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "users")
public class UserEntity {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private long id;
	private String userId;
	private String email;
	private String password;

	@Enumerated(EnumType.STRING)
	private Role role;

}
