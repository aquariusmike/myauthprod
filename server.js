import express from "express";
import session from "express-session";
import passport from "passport";
import dotenv from "dotenv";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";

dotenv.config();

const app = express();

// Session Middleware
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
  })
);

// Passport Init
app.use(passport.initialize());
app.use(passport.session());

// -----------------------
// GOOGLE OAUTH STRATEGY
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

      // --- ROLE LOGIC ---
      let role = "general"; // default for normal gmail

      if (email.endsWith("@stu.pathfinder-mm.org")) {
        role = "student";
      }

      // exception: allow your personal gmail as student
      if (email === "avagarimike11@gmail.com") {
        role = "student";
      }

      return done(null, { email, name: profile.displayName, role });
    }
  )
);

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// -----------------------
// ROUTES
// -----------------------

// Serve pages
app.use(express.static("public"));

// Redirect to Google
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

// Google Callback
app.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    failureRedirect: "/login.html",
  }),
  (req, res) => {
    res.redirect("/dashboard");
  }
);

// Middleware to protect dashboard
function ensureLoggedIn(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect("/login.html");
}

// Dashboard route
app.get("/dashboard", ensureLoggedIn, (req, res) => {
  const { name, email, role } = req.user;

  // Inject data into HTML (in a simple way)
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

// Logout
app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) {
      // Handle error if logout fails
      console.error("Logout Error:", err);
      return res.redirect("/"); 
    }
    
    req.session.destroy(() => {
      // CHANGE THIS: Redirect after successful logout to index.html
      res.redirect("/index.html");
    });
  });
});

// Start Server
app.listen(3000, () =>
  console.log("Server running on http://localhost:3000")
);
