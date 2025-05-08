# springboot-security-jwt-auth
Aplicación backend desarrollada con Spring Boot que implementa autenticación segura mediante Spring Security y JWT. Proporciona endpoints protegidos, gestión de usuarios y control de acceso basado en tokens.
Spring Data y Mysql tambien forman parte del codigo.

En este codigo, crearemos una aplicación Spring Boot compatible con la autenticación basada en tokens con JWT. Aprenderás:

Flujo adecuado para el registro e inicio de sesión de usuarios con autenticación JWT
Arquitectura de la aplicación Spring Boot con Spring Security
Cómo configurar Spring Security para trabajar con JWT
Cómo definir modelos de datos y asociaciones para la autenticación y la autorización
Cómo usar Spring Data JPA para interactuar con bases de datos PostgreSQL/MySQL

 

En la aplicacion a desarrollar, el usuario puede crear una nueva cuenta o iniciar sesión con nombre de usuario y contraseña.
Según su rol (administrador, moderador, usuario), le autorizamos a acceder a los recursos.
Estas son las API(endpoint) que necesitamos proporcionar:


Methods	Urls	Actions
POST	/api/auth/registrar	Registrar una nueva cuenta
POST	/api/auth/login	Iniciar sesión en una cuenta
GET	/api/test/all	recuperar contenido público
GET	/api/test/user	acceder al contenido del Usuario
GET	/api/test/mod	acceder al contenido del moderador
GET	/api/test/admin	acceder al contenido del administrador

Se debe agregar un JWT legal al encabezado(header) de autorización HTTP si el cliente accede a recursos protegidos
Colocar la palabre Bearer antes del token en el campo value.
