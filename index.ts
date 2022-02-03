require("dotenv").config();

import { createServer } from "http";
import { readFileSync } from "fs";
import express from "express";
import bodyparser from "body-parser";
import cookieParser from "cookie-parser";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-saml";

// User Object
import User from "./User";

// Passport Configuration
passport.serializeUser<Express.User>((user, done) => {
    done(null, user);
});

passport.deserializeUser<Express.User>((user, done) => {
    done(null, user);
});

// Create Strategy
const samlStrategy = new Strategy(
    {
        // URL that goes from the Identity Provider -> Service Provider
        callbackUrl: process.env.CALLBACK_URL,

        // URL that goes from the Service Provider -> Identity Provider
        entryPoint: process.env.ENTRY_POINT,

        // Usually specified as `/shibboleth` from site root
        issuer: process.env.ISSUER,
        identifierFormat: null,

        // Service Provider private key
        decryptionPvk: readFileSync(__dirname + "/cert/key.pem", "utf-8"),

        // Service Provider private key
        privateKey: readFileSync(__dirname + "/cert/key.pem", "utf-8"),

        // Identity Provider certificate
        cert: readFileSync(__dirname + "/cert/idp_cert.pem", "utf-8"),
    },
    (profile: any, done: any) => {
        return done(
            null,
            new User(profile.FirstName, profile.LastName, profile.email)
        );
    }
);

passport.use(samlStrategy);

// Create Express App
const app = express();

// Setup Middleware
app.use(bodyparser.urlencoded({ extended: false }));
app.use(bodyparser.json());
app.use(cookieParser());
app.use(
    session({
        name: "sp",
        secret: process.env.SESSION_SECRET as string,
        resave: true,
        saveUninitialized: true,
    })
);
app.use(passport.initialize());
app.use(passport.session());

// Ensure user is authenticated helper function
const ensureAuthenticated = (req: any, res: any, next: any) => {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect("/login");
};

// Setup Routes
app.get("/", ensureAuthenticated, (req: any, res: any) => {
    res.send(`Hello, ${req.user.FirstName} ${req.user.LastName}`);
});

app.get(
    "/login",
    passport.authenticate("saml", { failureRedirect: "/login" }),
    (_, res: any) => {
        res.redirect("/");
    }
);

app.post(
    "/login/callback",
    passport.authenticate("saml", { failureRedirect: "/login" }),
    (_, res: any) => {
        res.redirect("/");
    }
);

app.get("/login/fail", (_, res: any) => {
    res.status(401).send("Failed to authenticate");
});

app.get("/Shibboleth.sso/Metadata", (_, res: any) => {
    res.type("application/xml");
    res.status(200).send(
        samlStrategy.generateServiceProviderMetadata(
            readFileSync(__dirname + "/cert/cert.pem", "utf-8"),
            readFileSync(__dirname + "/cert/cert.pem", "utf-8")
        )
    );
});

// General Error Handler
app.use((err: any, req: any, res: any, next: any) => {
    console.log(`Fatal Error: ${JSON.stringify(err)}`);
    next(err);
});

// Create Server
const httpServer = createServer(app);

const port = process.env.PORT || 4006;
httpServer.listen(port, () => {
    console.log(`Listening on port ${port}`);
});
