const express = require('express');
const app = express();
const mysql = require('mysql');
const cors = require('cors');

const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');
const saltRounds = 10;

app.use(express.json());
app.use(cors({
    origin: ["http://localhost:3000"],
    methods: ["GET", "POST"],
    credentials: true
}));
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(
    session({
        key: "userId",
        secret: "subscribe",
        resave: false,
        saveUninitialized: false,
        cookie: {
            expires: 60 * 60 * 24,
        },
    })
);

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

app.get("/sign-in", (request, response) => {
    if (request.session.user) {
        response.send({
            loggedIn: true,
            user: request.session.user,
        })
    }
    else {
        response.send({
            loggedIn: false
        })
    }
})

app.post("/sign-in", (request, response) => {
    let username = request.body.username;
    let password = request.body.password;
    db.query("SELECT * FROM Users.users WHERE username=(?);", username, (error, result) => {
        if (result.length > 0) {
            bcrypt.compare(password, result[0].password, (e, r) => {
                if (r) {
                    request.session.user = result;
                    response.status(200).send({
                        message: `Welcome ${username}`
                    });
                }
                else {
                    response.status(400).send({
                        message: "Incorrect password"
                    })
                }
            })
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

    bcrypt.hash(password, saltRounds, (error, hash) => {
        if (error) {
            console.log(error)
        }
        else {
            db.query("SELECT * from Users.users WHERE username=(?);", username, (error, result) => {
                if (result.length > 0) {
                    response.status(400).send({
                        message: "User Already Registered"
                    })
                }
                else {
                    db.query("INSERT INTO users (username, password) VALUES (?, ?);", [username, hash], (error, result) => {
                        if (error) {
                            console.log(error)
                            response.status(400).send({
                                message: "Fail to Sign Up"
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
        }
    })
})
