const mysql = require("mysql");
require('dotenv').config();

const db = mysql.createConnection({
    user: process.env.database_user,
    host: process.env.database_host,
    password: process.env.database_password,
    database: process.env.database_schema,
});

const insertUserIntoDB = (username, hash, role) => {
    return new Promise(function (resolve, reject) {
        db.query("INSERT INTO users (username, password, role) VALUES (?, ?, ?);", [username, hash, role], (error, result) => {
            if (error) {
                reject(error);
            }
            else {
                resolve(result);
            }
        })
    })
}

const getUserByUsername = (username) => {
    return new Promise(function (resolve, reject) {
        db.query("SELECT * FROM Users.users WHERE username=(?);", username, (error, result) => {
            if (error) {
                reject(error);
            }
            else {
                resolve(result);
            }
        } )
    })
}

const getAllRoles = () => {
    return new Promise(function (resolve, reject) {
        db.query("SELECT DISTINCT role FROM Users.users", (error, result) => {
            if (error) {
                reject(error);
            }
            else {
                resolve(result);
            }
        })
    })
}

module.exports = {
    getAllRoles: getAllRoles,
    getUserByUsername: getUserByUsername,
    insertUserIntoDB: insertUserIntoDB
}
