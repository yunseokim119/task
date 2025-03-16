# Spring Boot 기반 JWT 인증/인가 및 AWS 배포

## 📌 프로젝트 개요
Spring Boot를 사용하여 회원가입, 로그인, 관리자 권한 부여 기능을 구현한 프로젝트입니다.

## 🌍 API 문서 (Swagger)
Swagger UI에서 API 명세서를 확인할 수 있습니다.

🔗 [Swagger UI 링크](http://98.80.73.150:8080/swagger-ui/index.html)

### 📁 API 목록

<details>
  <summary>🔹 1. 회원가입 (User Signup)</summary>

- **URL**: `POST /api/auth/signup`
- **설명**: 일반 사용자 계정을 생성합니다.
- **요청 예시**:
  ```json
  {
    "username": "newUser",
    "password": "password123",
    "nickname": "nickname"
  }
- **응답 예시(성공)**:
  ```json
  {
    "username": "newUser",
    "nickname": "nickname",
    "roles": [{"role": "USER"}]
  }
- **응답 예시 (실패 - 이미 존재하는 사용자)**:
  ```json
  {
  "error": {
    "code": "USER_ALREADY_EXISTS",
    "message": "해당 사용자는 이미 존재합니다." }
  }
</details>

<details>
  <summary>🔹 2. 관리자 회원가입 (Admin Signup)</summary>
  
- **URL**: `POST /api/auth/admin/signup`
- **설명**: 관리자가 새로운 관리자 계정을 생성합니다.
- **권한**: ADMIN 권한 필요
- **요청 예시**:
  ```json
  {
  "username": "adminUser",
  "password": "securePassword",
  "nickname": "adminNickname"
  }
- **응답 예시(성공)**:
  ```json
  {
  "username": "adminUser",
  "nickname": "adminNickname",
  "roles": [{"role": "ADMIN"}]
  }
- **응답 예시 (실패 - 이미 존재하는 사용자)**:
  ```json
  {
  "error": {
    "code": "USER_ALREADY_EXISTS",
    "message": "해당 사용자는 이미 존재합니다." }
  }
</details>

<details>
  <summary>🔹 3. 로그인 (Login)</summary>

- **URL**: `POST /api/auth/login`
- **설명**: 로그인하여 JWT 토큰을 발급받습니다.
- **요청 예시**:
  ```json
  {
  "username": "newUser",
  "password": "password123"
  }
- **응답 예시(성공)**:
  ```json
  {
  "token": "eyJhbGciOiJIUzI1NiIsIn..."
  }
- **응답 예시 (실패 - 아이디 또는 비밀번호 오류)**:
  ```json
  {
  "error": {
    "code": "INVALID_CREDENTIALS",
    "message": "아이디 또는 비밀번호가 올바르지 않습니다."
  }
  }
</details>

<details>
  <summary>🔹 4. 관리자 권한 부여 (Grant Admin Role)</summary>

- **URL**: `POST /api/auth/grant-admin/{username}`
- **설명**: 기존 일반 사용자에게 관리자 권한을 부여합니다.
- **권한**: ADMIN 권한 필요
- **요청 예시**:
  ```json
  {
  }
- **응답 예시(성공)**:
  ```json
  {
  "username": "JIN HO",
  "nickname": "Mentos",
  "roles": [
    {
      "role": "Admin"
    }
  ]
  }}
- **응답 예시 (실패 - 권한 부족)**:
  ```json
  {
  "error": {
    "code": "ACCESS_DENIED",
    "message": "관리자 권한이 필요한 요청입니다. 접근 권한이 없습니다."
  }
  }
</details>

## 🚀 배포 정보 (AWS EC2)
본 프로젝트는 AWS EC2에서 배포되었습니다.

- **EC2 Public IP**: `98.80.73.150`
- **접속 방법**: `http://98.80.73.150:8080`
- **실행 방법**:
  ```sh
  git clone https://github.com/yunseokim119/task.git
  cd task
  ./gradlew build
  java -jar build/libs/task-0.0.1-SNAPSHOT.jar
