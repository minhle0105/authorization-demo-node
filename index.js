const express = require('express');
const app = express();
const mysql = require('mysql');
const cors = require('cors');

app.use(cors());
app.use(express.json());

let usernames = new Set();

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
            console.log("ABC")
        }
    })
})

app.post("/sign-up", (request, response) => {
    let username = request.body.username;
    let password = request.body.password;

    if (usernames.has(username)) {
        response.status(400).send({
            message: "User already existed"
        });
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
                usernames.add(username);
            }
        })
    }
})
