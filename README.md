# Spring Security JWT

This project is an tutorial of a Backend API that performs the JWT (JSON web token) based authentication and authorization operations using Spring Boot. The user is designed to safely manage the registration, login and user information.

The main features of this project is:
- Stateless authentication with JWT
- Endpoint safety with Spring Security
- Password encoding with BCrypt
- RInfrastructure for Role-Based Authorization (Developable)
- PostgreSQL as database
- Docker support

## Project Structure

```
spring_security_jwt
├── aspect -> JWT authentication filter
├── config -> security configuration
├── controller -> REST API endpoints
├── dto -> data transfer objects
├── entity -> JPA entity class 
├── repository -> JPA repository
├── service -> UserService, JwtService, AuthenticationService
└── SpringSecurityJwtApplication.java

```

## Used Technologies
``` 
- Java 17
- Spring Boot 3.x
- Spring Security
- Spring Data JPA
- PostgreSQL
- JWT (jjwt)
- Lombok
- Docker / Docker Compose
```

## Usage

### Clone the project
```
git clone https://github.com/demirhany/spring_security_jwt.git
cd spring_security_jwt
```

### Go to directory ```docker/``` and start PostgreSQL
```
docker compose up -d
```
this step creates a db named as ``` jwt_security ``` and default password is ```1234```

### Go to directory ```spring_security_jwt/``` and run the application
```
./mvnw spring-boot:run
```

### API Endpoints
``` 
POST  /api/auth/register	new user registration
POST  /api/auth/login	    login and jwt token getting
GET	  /api/users/me	        return the logged user
GET	  /api/users	        return all users
```

### Test the endpoints with Postman
- First register a user
```
POST localhost:8080/api/auth/register
{
  "username": "demo",
  "password": "1234"
}
```
- Then login as this user and this will return a jwt token - copy it
```
POST localhost:8080/api/auth/login
{
  "username": "demo",
  "password": "1234"
}
```
- After that you can test all secured endpoints like ``` api/users/me ``` via the copied token. You need to go ```Authorization``` section in ```Postman``` and then set the ``` Auth Type ``` as ```Bearer Token``` and paste the copied ```token``` to empty blank.
```
GET localhost:8080/api/users/me
```

## Security Notes
- The passwords are reserved in the database by having with the ```BCRYPT algorithm```.

- The JWT Tokens are created with the JWTService class and confirmed.

- Session is not kept because it is used as a ```stateless architecture```.


**developer**: [demirhany](https://github.com/demirhany)
