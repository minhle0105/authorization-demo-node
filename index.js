const express = require('express');
const app = express();
const mysql = require('mysql');
const cors = require('cors');

const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');
const saltRounds = 10;

app.use(cors());
app.use(express.json());

const db = mysql.createConnection({
    user: 'root',
    host: 'localhost',
    password: 'minhle123',
    database: 'Users',
});


const PORT = 3001;
app.listen(PORT, () => {
    console.log(`Server listening on ${PORT}`)
})
app.post("/sign-in", (request, response) => {
    let username = request.body.username;
    let password = request.body.password;
    db.query("SELECT * FROM Users.users WHERE username=(?);", username, (error, result) => {
        if (result) {
            if (result[0].password === password) {
                response.status(200).send({
                    message: `Welcome ${username}`
                });
            }
            else {
                response.status(400).send({
                    message: "Incorrect password"
                })
            }
        }
        else {
            response.status(400).send({
                message: "User Not Found"
            })
        }
    })
})

app.post("/sign-up", (request, response) => {
    let username = request.body.username;
    let password = request.body.password;

    db.query("SELECT * from Users.users WHERE username=(?);", username, (error, result) => {
        if (result) {
            response.status(400).send({
                message: "User Already Registered"
            })
        }
        else {
            db.query("INSERT INTO users (username, password) VALUES (?, ?);", [username, password], (error, result) => {
                if (error) {
                    response.status(400).send({
                        message: "Fail to Sign In"
                    });
                }
                else {
                    response.status(201).send({
                        message: "Welcome new user"
                    });
                }
            })
        }
    })
})
