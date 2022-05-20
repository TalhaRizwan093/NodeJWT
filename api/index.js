const { response } = require("express");
const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");
app.use(express.json());

const users = [
    {
        id: 1,
        username: "talha",
        password: "talha1234",
        isAdmin: true,
    },
    {
        id: 2,
        username: "jhon",
        password: "jhon1234",
        isAdmin: false,
    },
]

let refreshTokens = [];

const generateAccessToken = (user) =>{
    return jwt.sign({id:user.id, isAdmin:user.isAdmin}, "myScretKey", { expiresIn: "5m"} )
}
const generateRefreshToken = (user) =>{
   return jwt.sign({id:user.id, isAdmin:user.isAdmin}, "myRefreshScretKey", { expiresIn: "15m"} )
}

const verify = (req,res,next) =>{
    const authHeader = req.headers.authorization;
    if(authHeader){
        const token = authHeader.split(" ")[1];

        jwt.verify(token, "myScretKey", (err, user) =>{
            if(err){
                return res.status(403).json("Token is not valid");
            }else{
                req.user = user;
                next();
            }
        });
    }else{
        res.status(401).json("Not authenticated")
    }
}

app.post("/api/refresh", (req,res) =>{
    //take token from user
    const refreshToken = req.body.token;


    //send error if token invalid
    if(!refreshToken) return res.status(401).json("You are not authenticated");
    if(!refreshTokens.includes(refreshToken)){
        return res.status(403).json("Refresh token is not valid");
    }

    //if ok create new token
    jwt.verify(refreshToken, "myRefreshScretKey", (err,user) => {
        err && console.log(err);
        refreshTokens = refreshTokens.filter((token) => token !== refreshToken);

        const newAccessToken = generateAccessToken(user);
        const newRefreshToken = generateRefreshToken(user);

        refreshTokens.push(newRefreshToken);
        res.status(200).json({
            accessToken: newAccessToken,
            refreshToken: newRefreshToken,
        })

    })
});

app.post("/api/logout", verify, (req,res)=>{
    const refreshToken = req.body.token;
    refreshTokens = refreshTokens.filter((token) => token !== refreshToken);
    res.status(200).json("you are logged out successfully");
})



app.post("/api/login", (req,res)=>{
    const {username, password} = req.body
    const user = users.find(u=>{
        return u.username === username && u.password === password;
    });
    if(user){
        //access token
        const accessToken = generateAccessToken(user);
        const refreshToken = generateRefreshToken(user);
        refreshTokens.push(refreshToken);
        res.json({
            username:user.username,
            isAdmin:user.isAdmin,
            accessToken,
            refreshToken,
        });
    }else{
        res.status(400).json("username or password incorrect");
    }
});




app.delete("/api/users/:userId", verify, (req,res) =>{

    if(req.user.id === parseInt(req.params.userId) || req.user.isAdmin ){
        res.status(200).json("user deleted");
    }else{
        res.status(403).json("not allowed to delete user");
    }
});



app.listen(5000, ()=> console.log("Backend Server running"));
