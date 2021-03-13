require('dotenv/config');
const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const { verify } = require('jsonwebtoken');
const { hash, compare } = require('bcryptjs');

const { fakeDB } = require('./fakeDB.js');
const { createAccessToken, createRefreshToken, sendRefreshToken, sendAccessToken } = require('./tokens.js');
const { isAuth } = require('./isAuth.js')

const server = express();

// use express middileware for easier cookie handling
server.use(cookieParser());

server.use(
    cors({
        origin: 'http://localhost:3000',
        credentials: true,
    })
)

// Needed to be able to read body data
server.use(express.json()); // to support json encoded body
server.use(express.urlencoded({ extended: true })); // to support URL-encoded bodies


// 1. Register a user
server.post('/register', async (req, res) => {
    const { email, password } = req.body;

    try {
        // 1. check if user exists
        console.log(fakeDB);
        const user = fakeDB.find(user => user.email === email);

        if (user) throw new Error('User already exists.');

        // 2. If not user exist, hash the password.
        const hashedPassword = await hash(password, 10);

        // insert the user in database.
        fakeDB.push({
            id: fakeDB.length,
            email: email,
            password: hashedPassword
        })

        res.send({ message: 'User Created.' });
        console.log(fakeDB);
    } catch (err) {
        res.send({ error: err.message })
    }
})

// 2. Login a user
server.post('/login', async (req, res) => {
    const { email, password } = req.body;
    console.log(email, password)
    try {
        // 1. Find user in database. If not send error message
        const user = fakeDB.find(user => user.email === email);
        if (!user) throw new Error("user does not exist.");

        // 2. Compare crypted password and see if it checks out. Send error if they not.
        const valid = await compare(password, user.password);
        if (!valid) throw new Error("Password not correct.");

        //3. Create refresh and access token
        const accessToken = createAccessToken(user.id);
        const refreshToken = createRefreshToken(user.id);

        // 4. Put refresh token in database
        user.refreshToken = refreshToken;
        console.log(fakeDB)

        // 5. Send token. Refresh toekn as a cookie and access tiken as a regular response
        sendRefreshToken(res, refreshToken);
        sendAccessToken(res, req, accessToken);

    } catch (err) {
        res.send({ error: `${err.message}` })
    }
})

// 3. Logout a user
server.post('/logout', (_req, res) => {
    res.clearCookie('refreshtoken', { path: '/refresh_token' });
    // Logic here for also remove refreshtoken from db
    return res.send({
        message: 'Logged out',
    });
});

// 4. Setup a protected route
server.post('/protected', async (req, res) => {
    try {
        const userId = isAuth(req)
        if (userId !== null) { res.send({ data: 'This is protected data.' }) }
    } catch (err) {
        res.send({ error: `${err.message}` })
    }
})

// 5. Get a new access token with a refresh token
server.post('/refresh_token', (req, res) => {
    const token = req.cookies.refreshtoken;
    // If we don't have a token in our request
    if (!token) return res.send({ accesstoken: '' });
    // We have a token, let's verify it!
    let payload = null;
    try {
        payload = verify(token, process.env.REFRESH_TOKEN_SECRET);
    } catch (err) {
        return res.send({ accesstoken: '' });
    }
    // token is valid, check if user exist
    const user = fakeDB.find(user => user.id === payload.userId);
    if (!user) return res.send({ accesstoken: '' });
    // user exist, check if refreshtoken exist on user
    if (user.refreshtoken !== token)
        return res.send({ accesstoken: '' });
    // token exist, create new Refresh- and accesstoken
    const accesstoken = createAccessToken(user.id);
    const refreshtoken = createRefreshToken(user.id);
    // update refreshtoken on user in db
    // Could have different versions instead!
    user.refreshtoken = refreshtoken;
    // All good to go, send new refreshtoken and accesstoken
    sendRefreshToken(res, refreshtoken);
    return res.send({ accesstoken });
});


server.listen(process.env.PORT), () => {
    console.log(`Server listening on port ${process.env.PORT}`);
}