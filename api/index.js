// api/index.js (Vercel-ready Express server)

import express from "express";
import session from "express-session";
import passport from "passport";
import dotenv from "dotenv";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import flash from "connect-flash";
import path from "path";
import { fileURLToPath } from "url";
import { createClient } from "redis";
import { RedisStore } from "connect-redis";

dotenv.config();

// Required because Vercel serverless breaks __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// -----------------------
// TRUST PROXY + STATIC FILES
// -----------------------
app.set("trust proxy", 1);

// Serve everything from /public
app.use(express.static(path.join(__dirname, "..", "public")));

// -----------------------
// REDIS SESSION STORE
// -----------------------
let redisClient;
let sessionStore;

if (process.env.KV_URL) {
  redisClient = createClient({ url: process.env.KV_URL });

  redisClient.on("error", err => console.error("Redis Error:", err));
  redisClient.on("connect", () => console.log("Redis Connected"));
  await redisClient.connect().catch(console.error);

  sessionStore = new RedisStore({
    client: redisClient,
    prefix: "sess:",
    ttl: 14 * 24 * 60 * 60,
  });
} else {
  console.log("⚠ Using in-memory session store (dev only)");
  sessionStore = undefined;
}

// -----------------------
// SESSION MIDDLEWARE
// -----------------------
app.use(
  session({
    store: sessionStore,
    secret: process.env.SESSION_SECRET || "change-me",
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
      maxAge: 14 * 24 * 60 * 60 * 1000
    }
  })
);

app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

// -----------------------
// GOOGLE LOGIN STRATEGY
// -----------------------
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: `${process.env.BASE_URL}/api/auth/google/callback`
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails[0].value;
        let role = "general";
        let isAuthorized = false;

        // Allowed student emails
        if (email.endsWith("@stu.pathfinder-mm.org") || email === "avagarimike11@gmail.com") {
          role = "student";
          isAuthorized = true;
        }

        if (!isAuthorized) {
          return done(null, false, {
            message: "You are not a verified student of Pathfinder Institute Myanmar."
          });
        }

        return done(null, {
          email,
          name: profile.displayName,
          role
        });
      } catch (err) {
        return done(err, null);
      }
    }
  )
);

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// -----------------------
// AUTH ROUTES
// -----------------------
app.get("/api/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/api/auth/google/callback",
  passport.authenticate("google", {
    failureRedirect: "/auth-failed.html",
    failureFlash: true
  }),
  (req, res) => res.redirect("/dashboard")
);

// -----------------------
// PROTECTED ROUTES
// -----------------------
function ensureLoggedIn(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect("/index.html");
}

// Return session info to dashboard
app.get("/api/session-info", ensureLoggedIn, (req, res) => {
  res.json({
    loggedIn: true,
    email: req.user.email,
    name: req.user.name,
    role: req.user.role
  });
});

// Serve dashboard (static)
app.get("/dashboard", ensureLoggedIn, (req, res) => {
  res.sendFile(path.join(__dirname, "..", "public", "dashboard.html"));
});

// Logout
app.get("/logout", (req, res) => {
  req.logout(() => {
    req.session.destroy(() => res.redirect("/index.html"));
  });
});

// -----------------------
// EXPORT FOR VERCEL
// -----------------------
export default app;
