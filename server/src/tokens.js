const { sign } = require('jsonwebtoken');

const createAccessToken = userID => {
    return sign({userID}, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: '15m'
    })
};

const createRefreshToken = userID => {
    return sign({userID}, process.env.REFRESH_TOKEN_SECRET, {
        expiresIn: '7d'
    })
};

const sendAccessToken = (req, res, accessToken) => {
    res.send({
        accessToken,
        email: req.body.email
    })
};

const sendRefreshToken = (res, refreshToken) => {
    res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        path: '/refresh_token'
    })
}
module.exports = {
    createAccessToken,
    createRefreshToken,
    sendAccessToken,
    sendRefreshToken
}