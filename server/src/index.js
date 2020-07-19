require('dotenv/config');
const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const {hash, compare} = require('bcryptjs');
const { fakeDB } = require('./fakeDB');
const server = express();
const { createAccessToken, 
        createRefreshToken,
        sendAccessToken, 
        sendRefreshToken } = require('./tokens');

const {isAuth} = require('./isAuth');
const { verify } = require('jsonwebtoken');
server.use(cookieParser());
server.use(cors({
    origin: 'http://localhost:3000',
    credentials: true,
}));

server.use(express.json());
server.use(express.urlencoded({ extended: true })); //support url encoded bodies
server.listen(process.env.PORT, () => {
    console.log(`server started at port ${process.env.PORT}`)
});

server.post('/register', async(req, res) => {
    const {email, password} = req.body;
    
    try {
        const user = fakeDB.find(user => user.email === email);
        if(user) {
            throw new Error('User already exists!');
        }
        const hashedPassword = await hash(password, 10);
        fakeDB.push({
            id: fakeDB.length,
            email,
            password: hashedPassword
        });
        console.log(fakeDB);
        res.send({message: "User Created!"});
    }
    catch(err) {
        res.send({
            error: `${err.message}`
        })
    }
});

server.post('/login', async (req, res) => {
    const {email, password} = req.body;

    try {
        const user = fakeDB.find(user => user.email === email);
        if(!user) throw new Error(`User does not exists!`);
        const valid = await compare(password, user.password);
        if(!valid) throw new Error(`Password not correct`);
        //create refresh and access tokens
        const accessToken =  createAccessToken(user.id);
        const refreshToken = createRefreshToken(user.id);
        //put refreshToken in database
        user.refreshToken = refreshToken;
        //send refresh token as a cookie and access token as a regular response
        sendRefreshToken(res, refreshToken);
        sendAccessToken(req, res, accessToken);
        console.log(fakeDB);

    }
    catch(err) {
        res.send({
            error: `${err.message}`
        })
    }
});

server.post('/logout', (req, res) => {
    res.clearCookie('refreshToken', {path: '/refresh_token'});
    return res.send({
        message: "Logged out"
    })
});

server.get('/user', async (req, res) => {
    try {
        const userId = isAuth(req);
        if(userId !== null) {
            const user = fakeDB.find(user => user.id === userId);
            res.send({
                user
            });
        }
        else throw new Error('UnAuthorized!')
    }
    catch(err) {
        res.send({
            error: `${err.message}`
        })
    }
});

//get a new access token with refresh token
server.post('/refresh_token', async (req, res) => {
    const token = req.cookies.refreshToken;
    //if we dont have a token in req
    if(!token) {
        return res.send({ accessToken: " " });
    }
    let payload = null;
    try {
        payload = verify(token, process.env.REFRESH_TOKEN_SECRET);
    }
    catch(err) {
        return res.send({
            accessToken: " " 
        })
    }
    //token is valid, check if user exists
    const user = fakeDB.find(user => user.id === payload.userID);
    if(!user) {
        return  res.send({
            accessToken: " " 
        })
    }
    //check if refresh token exists on user
    if(user.refreshToken !== token ) {
        return  res.send({
            accessToken: " " 
        })
    }
    //token exists create new refresh and access token
    const accessToken = createAccessToken(user.id);
    const refreshToken = createRefreshToken(user.id);
    user.refreshToken = refreshToken;
    //send new refresh token and access token
    sendRefreshToken(res, refreshToken);
    return res.send({accessToken});
});