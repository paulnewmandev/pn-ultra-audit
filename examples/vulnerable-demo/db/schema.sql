CREATE TABLE users (id INT, email VARCHAR(100), password VARCHAR(32), price FLOAT);
CREATE TABLE orders (id INT PRIMARY KEY, user_id INT, total FLOAT, FOREIGN KEY (user_id) REFERENCES users(id)) ENGINE=MyISAM;
GRANT ALL PRIVILEGES ON *.* TO 'app'@'%';
CREATE USER 'app'@'%' IDENTIFIED BY 'plainpass1';
