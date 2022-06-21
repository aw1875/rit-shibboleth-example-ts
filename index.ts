require("dotenv").config();

import { createServer } from "http";
import { readFileSync } from "fs";
import express, { Request, Response, NextFunction } from "express";
import bodyparser from "body-parser";
import cookieParser from "cookie-parser";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-saml";

// Types
import User from "./@types/User";

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
      return done(null, new User(profile.FirstName, profile.LastName, profile.Email, profile["urn:oid:1.3.6.1.4.1.4447.1.41"].includes("Student")));
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

/**
 * Ensure the user is authenticated.
 *
 * @param {Request} req Express Request
 * @param {Response} res Express Response
 * @param {NextFunction} next Express NextFunction
 * @returns {void}
 */
const ensureAuthenticated = (req: Request, res: Response, next: NextFunction) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/login");
};


/**
 * Main Route
 *
 * @name GET /
 * @property {Request} req Express Request
 * @property {Response} res Express Response
 * @returns {void} 
 */
app.get("/", ensureAuthenticated, (req: Request, res: Response): void => {
    req.user && res.send(`Hello, ${req.user.FirstName} ${req.user.LastName}`);
});

/**
 * Login Route
 *
 * @name GET /login
 * @property {Response} res Express Response
 * @returns {void}
 */
app.get(
  "/login",
  passport.authenticate("saml", { failureRedirect: "/login" }),
  (_, res: Response) => {
    res.redirect("/");
  }
);

/**
 * Login Callback Route
 *
 * @name GET /login/callback
 * @property {Response} res Express Response
 * @return {void}
 */
app.post(
  "/login/callback",
  passport.authenticate("saml", { failureRedirect: "/login" }),
  (_, res: Response) => {
    res.redirect("/");
  }
);

/**
 * Login Failed Route
 *
 * @name GET /login/fail
 * @property {Response} res Express Response
 * @returns {void}
 */
app.get("/login/fail", (_, res: Response) => {
  res.status(401).send("Failed to authenticate");
});

/**
 * Shibboleth Metadata Route
 *
 * @name GET /Shibboleth.sso/Metadata
 * @property {Response} res Express Response
 * @returns {void}
 */
app.get("/Shibboleth.sso/Metadata", (_, res: Response) => {
  res.type("application/xml");
  res
    .status(200)
    .send(
      samlStrategy.generateServiceProviderMetadata(
        readFileSync(__dirname + "/cert/cert.pem", "utf-8"),
        readFileSync(__dirname + "/cert/cert.pem", "utf-8")
      )
    );
});

/**
 * General Error Handler
 * 
 * @param {any} err Error to be displayed
 * @param {Request} _ Express Request
 * @param {Response} res Express Response
 * @param {NextFunction} next Express NextFunction
 * @returns {void}
 */
app.use((err: any, _: Request, res: Response, next: NextFunction) => {
  console.log(`Fatal Error: ${JSON.stringify(err)}`);
  next(err);
});

// Create Server
const httpServer = createServer(app);

const port = process.env.PORT || 4006;
httpServer.listen(port, () => {
  console.log(`Listening on port ${port}`);
});
