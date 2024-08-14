import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as GoogleStrategy } from "passport-google-oauth2";
import session from "express-session";
import dotenv from "dotenv";
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import flash from "connect-flash";
import crypto from "crypto";
import nodemailer from "nodemailer";

const app = express();
const port = 3000;
const saltRounds = 10;
dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Middleware setup
app.use(
    session({
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: true,
    })
);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(join(__dirname, 'public')));
app.use(flash());

// View engine setup
app.set('view engine', 'ejs');

app.use(passport.initialize());
app.use(passport.session());

// PostgreSQL client setup
const db = new pg.Client({
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    password: process.env.PG_PASSWORD,
    port: process.env.PG_PORT,
});
db.connect();

// Routes
app.get('/', (req, res) => {
    res.sendFile(join(__dirname, 'public', 'index.html'));
});

app.get("/login", (req, res) => {
    res.render("login");
});

app.get("/register", (req, res) => {
    res.render("register");
});

app.get("/logout", function (req, res, next) {
    if (req.session.login) {
        req.session.login = false;
        res.redirect("/");
    } else {
        res.redirect("/");
    }
});

function generateResetToken() {
    return crypto.randomBytes(32).toString('hex');
}

app.get('/forgot-password', (req, res) => {
    res.render('forgot-password');
});

app.post('/forgot-password', async (req, res) => {
    const email = req.body.email;
    try {
        const result = await db.query('SELECT * FROM users WHERE email = $1', [
            email
        ]);
        
        if(result.rows.length > 0) {
            const user = result.rows[0];
            const token = generateResetToken();
            const expiration = new Date(Date.now() + 3600000); // 24 hr expiration

            await db.query('UPDATE users SET reset_token = $1, reset_token_expiration = $2 WHERE email = $3', [token, expiration, email]);

            sendResetEmail(email, `http://localhost:${port}/reset-password/${token}`);

            res.send("Password recent link is sent to email, Please check your email");
        }else {
            res.send("Email not found");
        }
    }catch (err) {
        console.log(err);
        res.status(500).json({message: "Server Err"});
    }
});

app.get("/reset-password/:token", async (req, res) => {
    const { token } = req.params;
    try {
        // > $2 because it will select the col where the filter is after $2 to handle the token expiration
        const result = await db.query('SELECT * FROM users WHERE reset_token = $1 AND reset_token_expiration > $2', [token, new Date()]);

        if(result.rows.length > 0) {
            res.render('reset-password', { token });
        }else {
            res.send("Sorry Your Token is Expired !");
        }
    }catch (err) {
        console.log(err);
        res.status(500).json({ message: "Server Error"});
    }
});

app.post("/reset-password/:token", async (req, res) => {
    const { token } = req.params;
    const { password } = req.body;

    try {
        const result = await db.query('SELECT * FROM users WHERE reset_token = $1 AND reset_token_expiration > $2', [token, new Date()]);

        if(result.rows.length > 0) {
            const hashPassword = await bcrypt.hash(password, saltRounds);

            await db.query('UPDATE users SET password = $1, reset_token = null, reset_token_expiration = null WHERE reset_token = $2', [hashPassword, token]);
            res.send("Password has been successfully reset.");
            console.log(token);            
        }else {
            res.status(400).json({ message: "token generation err or expired!"});
        }
    }catch (err) {
        console.log(err);
        res.status(500).json({ message: "Server Err"});
    }
});

function sendResetEmail(to, link) {
    const transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
            user: process.env.USER_EMAIL,
            pass: process.env.USER_PASS
        },
    });

    const mailOptions = {
        from: process.env.USER_EMAIL,
        to,
        subject: "password reset link",
        text: `You requested a password reset. Click this link to reset your password: ${link}`,
    };

    transporter.sendMail(mailOptions, function(error, info){
        if (error) {
            console.log('Error sending email', error);
        } else {
            console.log('Email sent: ' + info.response);
            console.log('Sending email to:', to);
        }
    }
)};

app.get(
    "/auth/google",
    passport.authenticate("google", {
        scope: ["profile", "email"],
    })
);

app.get(
    "/auth/google/secrets",
    passport.authenticate("google", {
        successRedirect: "/",
        failureRedirect: "/login",
    })
);

app.post('/login', passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true // You might want to use flash messages for errors
}));

app.post("/register", async (req, res) => {
    const email = req.body.username;
    const password = req.body.password;

    try {
        const response = await db.query('SELECT * FROM users WHERE email = $1', [
            email,
        ]);

        if (response.rows.length > 0) {
            res.redirect("/login");
        } else {
            bcrypt.hash(password, saltRounds, async (err, hash) => {
                if (err) {
                    console.log("Error registering !", err);
                } else {
                    const result = await db.query('INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *', [
                        email, hash
                    ]);

                    const user = result.rows[0];
                    req.login(user, (err) => {
                        console.log("Login Successful");
                        res.redirect("/login");
                    });
                }
            });
        }
    } catch (err) {
        console.log(err);
    }
});

passport.use("local",
    new LocalStrategy(async function verify(username, password, cb) {
        try {
            const result = await db.query('SELECT * FROM users WHERE email = $1', [
                username,
            ]);

            if (result.rows.length > 0) {
                const user = result.rows[0];
                const storedHashedPassword = user.password;
                bcrypt.compare(password, storedHashedPassword, (err, valid) => {
                    if (err) {
                        console.log("Password does not match", err);
                        return cb(err);
                    } else {
                        if (valid) {
                            return cb(null, user);
                        } else {
                            return cb(null, false, {message: "Incorrect Password!"});
                        }
                    }
                })
            } else {
                return cb(null, false, { message: 'User not found' });
            }
        } catch (err) {
            res.status(404).json({message: "Error"});
        }
    })
);

passport.use(
    "google",
    new GoogleStrategy({
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: "http://localhost:3000/auth/google/secrets",
        userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
        async (accessToken, refreshToken, profile, cb) => {
            console.log(profile); // get the details of profile
            try {
                const result = await db.query('SELECT * FROM users WHERE email = $1', [
                    profile.email,
                ]);

                if (result.rows.length === 0) {
                    const newUser = await db.query('INSERT INTO users (email, password) VALUES ($1, $2)', [
                        profile.email, "google"
                    ]);
                    return cb(null, newUser.rows[0]);
                } else {
                    return cb(null, newUser.rows[0]);
                }
            } catch (err) {
                cb(err);
            }
        })
);

// Serialize the user into the session
passport.serializeUser((user, done) => {
    done(null, user.email);
});

// Deserialize the user from the session
passport.deserializeUser(async (email, done) => {
    try {
        const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length > 0) {
            done(null, result.rows[0]);
        } else {
            done(new Error("User not found"), null);
        }
    } catch (err) {
        done(err, null);
    }
});


// Start server
app.listen(port, () => {
    console.log(`Server is listening on port ${port}`);
});