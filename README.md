# sec_bloglight


A secure light weight blog system.



## Deployment

Two env. variable needs to be set before running this app:  
- PORT
- ADMIN_PASSWD the password for admin
- SESSION_SECRET  session secrect key, optional 

to set env. var, use `export PORT=2003` or use `etc/systemd/system/service_name.service` method.


## Usage

1. admin:  /admin/login
2. 