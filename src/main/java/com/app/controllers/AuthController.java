package com.app.controllers;

import java.util.HashSet;
import java.util.List;
 
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
 
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.app.models.ERole;
import com.app.models.Role;
import com.app.models.User;
import com.app.payload.JwtResponse;
import com.app.payload.LoginRequest;
import com.app.payload.MessageResponse;
import com.app.payload.SignupRequest;
import com.app.repository.RoleRepository;
import com.app.repository.UserRepository;
import com.app.security.jwt.JwtUtils;
import com.app.security.service.UserDetailsImpl;
import com.app.security.service.UserDetailsServiceImpl;
import jakarta.validation.Valid;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserDetailsServiceImpl userDetailsServiceImpl;
	/*
	 * AuthenticationManager cuenta con un DaoAuthenticationProvider (con la ayuda de UserDetailsService y PasswordEncoder)
	 *  para validar el objeto UsernamePasswordAuthenticationToken. 
	 *  Si se realiza correctamente, AuthenticationManager devuelve un objeto de autenticación completo 
	 *  (incluidas las autorizaciones otorgadas).
	 * */
	  @Autowired
	  AuthenticationManager authenticationManager;
	
	  @Autowired
	  UserRepository userRepository;

	  @Autowired
	  RoleRepository roleRepository;
	  
	  @Autowired
	  PasswordEncoder encoder;

	  @Autowired
	  JwtUtils jwtUtils;

    AuthController(UserDetailsServiceImpl userDetailsServiceImpl) {
        this.userDetailsServiceImpl = userDetailsServiceImpl;
    }
//este es el endpoint que al logearte genera el token
	  @PostMapping("/login")
	  public ResponseEntity<?> loginUsuario(@Valid @RequestBody LoginRequest loginRequest){
		  Authentication authentication = authenticationManager.authenticate(
			        new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
		  /*
		   * – UsernamePasswordAuthenticationToken obtiene {nombre de usuario, contraseña} de la solicitud de inicio de sesión,
		   *  AuthenticationManager lo utilizará para autenticar una cuenta de inicio de sesión.
		   * */
		  SecurityContextHolder.getContext().setAuthentication(authentication);
		  String jwt = jwtUtils.generateJwtToken(authentication);
		  
		  UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
		  List<String> roles = userDetails.getAuthorities().stream()
				  .map(item -> item.getAuthority())
				  .collect(Collectors.toList());
		  
		  
		  return ResponseEntity.ok(new JwtResponse(jwt, 
				  userDetails.getId(), 
				  userDetails.getUsername(),
				  userDetails.getEmail(), roles));		  
	  }
	  //este es el endpoint que registra el usuario
	  @PostMapping("/registrar")
	  public ResponseEntity<?> registrarUsuario(@Valid @RequestBody SignupRequest  signupRequest){
		  if(userRepository.existsByUsername(signupRequest.getUsername())) {
			  return ResponseEntity
					  .badRequest()
					  .body(new MessageResponse("Error: Nombre de Usuario ya existe!!"));
		  }
		  
		  if(userRepository.existsByEmail(signupRequest.getEmail())) {
			  return ResponseEntity
					  .badRequest()
					  .body(new MessageResponse("Error: Email de Usuario ya existe!!"));
					  
		  }
		  //Se crea la nueva cuenta
		  
		  User user = new User(signupRequest.getUsername(), 
				  				signupRequest.getEmail(),
				  encoder.encode(signupRequest.getPassword()));
		  
		  Set<String> strRole = signupRequest.getRole();
		  Set<Role> roles = new HashSet<>();
		  
		  if(strRole == null) {
			  Role userRole = roleRepository.findByName(ERole.ROLE_USER)
					  .orElseThrow(()-> new RuntimeException("Error: Role no encontrado."));
			  roles.add(userRole);
		  }else {
			  strRole.forEach(role ->{
				  switch (role) {
				case "admin": 
					Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
					.orElseThrow(() -> new RuntimeException("Error: Role no encontrado."));
					roles.add(adminRole);
					break;
					
				case "mod": 
					Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
					.orElseThrow(() -> new RuntimeException("Error: Role no encontrado."));
					roles.add(modRole);
					break;
					
				default:
			          Role userRole = roleRepository.findByName(ERole.ROLE_USER)
		              .orElseThrow(() -> new RuntimeException("Error: Role no encontrado."));
		          roles.add(userRole);
				}
			  });
		  }
		  user.setRoles(roles);
		  userRepository.save(user);
		  return ResponseEntity.ok(new MessageResponse("Usuario Registrado Exitosamente!."));
		  
	  }
}

