import express from "express";
import session from "express-session";
import passport from "passport";
import dotenv from "dotenv";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import flash from "connect-flash";
import MongoStore from "connect-mongo"; // <-- REQUIRED FOR PRODUCTION SESSIONS

dotenv.config();

const app = express();

// -----------------------
// 1. MIDDLEWARE
// -----------------------

// Session Middleware (Configured with MongoStore for Production Stability)
app.use(
  session({
    // --- PRODUCTION SESSION STORE ---
    store: MongoStore.create({
      mongoUrl: process.env.MONGO_URI, // Requires the MONGO_URI ENV variable
      ttl: 14 * 24 * 60 * 60, // Session expiration (14 days)
      collectionName: 'sessions',
    }),
    // --------------------------------
    secret: process.env.SESSION_SECRET, // Requires the SESSION_SECRET ENV variable
    resave: false,
    saveUninitialized: false,
  })
);

// Passport and Flash Initialization
app.use(passport.initialize());
app.use(passport.session());
app.use(flash()); // Required to show unauthorized messages

// -----------------------
// 2. GOOGLE OAUTH STRATEGY
// -----------------------
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: `${process.env.BASE_URL}/auth/google/callback`,
    },
    async (accessToken, refreshToken, profile, done) => {
      const email = profile.emails[0].value;

      // --- AUTHORIZATION LOGIC ---
      let role = "general";
      let isAuthorized = false;

      // Condition 1: Official Student Email
      if (email.endsWith("@stu.pathfinder-mm.org")) {
        role = "student";
        isAuthorized = true;
      }

      // Condition 2: Personal Gmail Exception
      if (email === "avagarimike11@gmail.com") {
        role = "student";
        isAuthorized = true;
      }

      // --- REJECTION STEP: Deny unauthorized users ---
      if (!isAuthorized) {
        // Calling done(null, false) triggers failureRedirect and stores the flash message.
        return done(null, false, { message: "You are not verified student of Pathfinder Institute Myanmar." });
      }

      // --- SUCCESS STEP ---
      return done(null, { email, name: profile.displayName, role });
    }
  )
);

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// -----------------------
// 3. ROUTES
// -----------------------

// Serve static files from the 'public' directory
app.use(express.static("public"));

// Redirect to Google for authentication
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

// Google Callback (Handles success and failure)
app.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    failureRedirect: "/auth/failure", // Redirects to our dynamic failure route
    failureFlash: true // Required to carry the rejection message
  }),
  (req, res) => {
    // Success: Redirect to dashboard
    res.redirect("/dashboard");
  }
);

// Handle Login Failure: Extracts flash message and redirects to index.html with error
app.get("/auth/failure", (req, res) => {
  const messages = req.flash("error");
  const errorMessage = messages.length > 0
    ? messages[0]
    : "Login failed.";
  
  // Redirect with the error message encoded in a query parameter
  const encodedMessage = encodeURIComponent(errorMessage);
  res.redirect(`/index.html?authError=${encodedMessage}`);
});

// Middleware to protect dashboard (Ensure the user is logged in)
function ensureLoggedIn(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect("/index.html"); // Redirect to index.html if not logged in
}

// Dashboard route (Renders HTML dynamically based on user role)
app.get("/dashboard", ensureLoggedIn, (req, res) => {
  const { name, email, role } = req.user;

  res.send(`
    <html>
    <head>
      <title>Dashboard</title>
      <style>
        body { font-family: Arial; padding: 20px; }
        .card { padding: 20px; border: 1px solid #ddd; border-radius: 10px; }
        .stu { background: #e3f2fd; }
        .gen { background: #fff3e0; }
      </style>
    </head>
    <body>
      <h2>Welcome ${name}</h2>
      <p>Email: ${email}</p>
      <p>Role: <b>${role}</b></p>

      ${
        role === "student"
          ? `<div class="card stu"><h3>Student Docs Section</h3></div>`
          : `<div class="card gen"><h3>Enrollment Section</h3></div>`
      }

      <br>
      <a href="/logout">Logout</a>
    </body>
    </html>
  `);
});

// Logout route
app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) {
      console.error("Logout Error:", err);
      return res.redirect("/");
    }

    req.session.destroy(() => {
      // Successful logout: Redirect to index.html
      res.redirect("/index.html");
    });
  });
});

// Start Server
app.listen(3000, () =>
  console.log("Server running on http://localhost:3000")
);