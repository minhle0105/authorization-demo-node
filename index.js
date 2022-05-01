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
    user: 'root',
    host: 'localhost',
    password: 'minhle123',
    database: 'Users',
});


const PORT = 3001;

const verifyJwt = (request, response, next) => {
    const token = request.headers.authorization;
    if (!token) {
        console.log("No token detected")
        response.status(401);
    }
    else {
        jwt.verify(token, "jwtSecret", (error, user) => {
            if (error) {
                console.log("Token not verified")
                response.status(403).send({
                    auth: false,
                    message: "Invalid token"
                });
            }
            else {
                console.log("verified")
                request.userId = user.id;
                next();
            }
        })
    }
}

function generateJwt (id) {
    return jwt.sign({id}, "jwtSecret", {
        expiresIn: 600
    });
}

app.listen(PORT, () => {
    console.log(`Server listening on ${PORT}`)
})

app.get("/roles", verifyJwt, (request, response) => {
    db.query("SELECT DISTINCT role FROM Users.users", (error, result) => {
        if (error) {
            console.log(error);
            response.status(500).send({
                message: "Cannot get roles"
            })
        }
        else {
            response.status(200).send(result);
        }
    })
})

app.post("/sign-in", (request, response) => {
    let username = request.body.username;
    let password = request.body.password;
    db.query("SELECT * FROM Users.users WHERE username=(?);", username, (error, result) => {
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
})

app.post("/sign-up", verifyJwt, (request, response) => {
    let username = request.body.username;
    let password = request.body.password;
    let role = request.body.role;
    console.log("Sign up request received");

    bcrypt.hash(password, saltRounds, (error, hash) => {
        if (error) {
            console.log(error)
        }
        else {
            db.query("SELECT * from Users.users WHERE username=(?);", username, (error, result) => {
                if (result.length > 0) {
                    response.status(400).send({
                        message: "User Already Registered"
                    });
                }
                else {
                    db.query("INSERT INTO users (username, password, role) VALUES (?, ?, ?);", [username, hash, role], (error, result) => {
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
