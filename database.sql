CREATE DATABASE ctf;
USE ctf;

CREATE TABLE IF NOT EXISTS players (
    username VARCHAR(255) PRIMARY KEY,
    password VARCHAR(255),
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    total_points INT DEFAULT 0
);

CREATE TABLE IF NOT EXISTS flags (
    flag VARCHAR(255) PRIMARY KEY,
    points INT
);

CREATE TABLE IF NOT EXISTS player_flags (
    username VARCHAR(255),
    flag VARCHAR(255),
    FOREIGN KEY (username) REFERENCES players(username),
    FOREIGN KEY (flag) REFERENCES flags(flag)
);







CREATE TABLE IF NOT EXISTS players (
    username VARCHAR(255) PRIMARY KEY,
    password VARCHAR(255),
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    ctf_program VARCHAR(255),
    total_points INT DEFAULT 0
);

CREATE TABLE IF NOT EXISTS flags (
    flag VARCHAR(255) PRIMARY KEY,
    flag_where VARCHAR(255) PRIMARY KEY,
    points INT
);

CREATE TABLE IF NOT EXISTS player_flags (
    username VARCHAR(255),
    flag VARCHAR(255),
    FOREIGN KEY (username) REFERENCES players(username),
    FOREIGN KEY (flag) REFERENCES flags(flag)
);