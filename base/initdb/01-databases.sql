-- 为本地 docker-compose 初始化两个独立数据库与角色。
CREATE ROLE auth_center LOGIN PASSWORD 'auth_center';
CREATE ROLE user_center LOGIN PASSWORD 'user_center';

CREATE DATABASE auth_center OWNER auth_center;
CREATE DATABASE user_center OWNER user_center;

GRANT ALL PRIVILEGES ON DATABASE auth_center TO auth_center;
GRANT ALL PRIVILEGES ON DATABASE user_center TO user_center;
