const express = require('express');
const app = express();
const cors = require('cors');
const morgan = require('morgan');
const file = require("rotating-file-stream")

const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');
const saltRounds = 10;

const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const service = require("./service");
const path = require("path");

require('dotenv').config();

app.use(express.json());
app.use(cors({
    origin: ["http://localhost:3000"],
    methods: ["GET", "POST"],
    credentials: true
}));
app.use(cookieParser());
app.use(bodyParser.urlencoded({extended: true}));

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


const devLogStream = file.createStream("dev.log", {
    size: '10M',
    interval: '7d'
})
const combineLogStream = file.createStream("combine.log", {
    size: '10M',
    interval: '7d'
})
app.use(morgan("dev", {
    stream: devLogStream
}));
app.use(morgan("combined", {
    stream: combineLogStream
}));

const PORT = process.env.PORT;
const jwtSecret = crypto.createHash(process.env.encryptAlgorithm).update(process.env.jwtSecret, 'utf-8').digest('hex');

const verifyJwt = (request, response, next) => {
    const token = request.headers.authorization;
    if (!token) {
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

    service.getAllRoles()
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
    if (!username || !password) {
        response.status(400).json({
            message: "Missing username or password"
        })
    }
    else {
        service.getUserByUsername(username)
            .then((result) => {
                if (result.length > 0) {
                    bcrypt.compare(password, result[0].password, (e, r) => {
                        if (r) {
                            const id = result[0].id;
                            const token = generateJwt(id);
                            request.session.user = result;
                            response.status(200).json({
                                auth: true,
                                token: token,
                                result: result
                            })
                        } else {
                            response.status(401).json({
                                auth: false,
                                message: "Incorrect password"
                            })
                        }
                    })
                }
                else {
                    response.status(401).json({
                        auth: false,
                        message: "User not found"
                    })
                }
            })
            .catch((error) => {
                console.log(error);
                response.status(401).json({
                    message: "Cannot sign-in"
                })
            })
    }
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
            service.getUserByUsername(username)
                .then((result) => {
                    if (result.length > 0) {
                        response.status(400).send({
                            message: "User Already Registered"
                        });
                    }
                    else {
                        service.insertUserIntoDB(username, hash, role)
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

app.get("/sign-out", (request, response) => {
    const session = request.session;
    if (session) {
        request.session = null;
    }
    response.status(200).json({
        message: "Successfully log out"
    });
})
