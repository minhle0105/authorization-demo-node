const express = require('express');
const app = express();
const mysql = require('mysql');

const PORT = 3001;
app.listen(PORT, () => {
    console.log(`Server listening on ${PORT}`)
})
app.get("/", (request, response) => {
    response.send("Hello World")
})
