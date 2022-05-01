const express = require('express');
const app = express();
const mysql = require('mysql');
const cors = require('cors');

const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');
const saltRounds = 10;

const jwt = require('jsonwebtoken');
const crypto = require('crypto');

require('dotenv').config();

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
            expires: 600000,
        },
    })
);

const db = mysql.createConnection({
    user: process.env.database_user,
    host: process.env.database_host,
    password: process.env.database_password,
    database: process.env.database_schema,
});


const PORT = process.env.PORT;
const jwtSecret = crypto.createHash(process.env.encryptAlgorithm).update(process.env.jwtSecret, 'utf-8').digest('hex');

const verifyJwt = (request, response, next) => {
    const token = request.headers.authorization;
    if (!token) {
        console.log("No token detected")
        response.status(401);
    }
    else {
        jwt.verify(token, jwtSecret, (error, user) => {
            if (error) {
                response.status(403).send({
                    auth: false,
                    message: "Invalid token"
                });
            }
            else {
                request.userId = user.id;
                next();
            }
        })
    }
}

function generateJwt (id) {
    return jwt.sign({id}, jwtSecret, {
        expiresIn: 600
    });
}

app.listen(PORT, () => {
    console.log(`Server listening on ${PORT}`)
})

app.get("/roles", verifyJwt, (request, response) => {

    getAllRoles()
        .then((result) => {
            response.status(200).send(result);
        })
        .catch((error) => {
            console.log(error);
            response.status(500).send({
                message: "Cannot get roles"
            })
        })
})

app.post("/sign-in", (request, response) => {
    let username = request.body.username;
    let password = request.body.password;

    getUserByUsername(username)
        .then((result) => {
            if (result.length > 0) {
                bcrypt.compare(password, result[0].password, (e, r) => {
                    if (r) {
                        const id = result[0].id;
                        const token = generateJwt(id);
                        request.session.user = result;
                        response.json({
                            auth: true,
                            token: token,
                            result: result
                        })
                    } else {
                        response.json({
                            auth: false,
                            message: "Incorrect password"
                        })
                    }
                })
            }
            else {
                response.json({
                    auth: false,
                    message: "User not found"
                })
            }
        })
        .catch((error) => {
            console.log(error);
            response.json({
                message: "Cannot sign-in"
            })
        })
})

app.post("/sign-up", verifyJwt, (request, response) => {
    let username = request.body.username;
    let password = request.body.password;
    let role = request.body.role;

    bcrypt.hash(password, saltRounds, (error, hash) => {
        if (error) {
            console.log(error)
        }
        else {
            getUserByUsername(username)
                .then((result) => {
                    if (result.length > 0) {
                        response.status(400).send({
                            message: "User Already Registered"
                        });
                    }
                    else {
                        insertUserIntoDB(username, hash, role)
                            .then((result) => {
                                response.status(201).send({
                                    message: "Successfully Registered"
                                });
                            })
                            .catch((error) => {
                                console.log(error)
                                response.status(400).send({
                                    message: "Fail to Sign Up"
                                });
                            });
                    }
                })
                .catch((error) => {
                    response.status(500).send(error);
                })
        }
    })
})

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
