require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const path = require('path');
const bcrypt = require('bcryptjs');

const app = express();

// --- RENDER DEPLOYMENT CONFIGURATION ---
app.set('trust proxy', 1); 

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// --- EMBEDDED CSS ---
const cssStyles = `
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}

body {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  padding: 20px;
}

.background {
  width: 100%;
  display: flex;
  justify-content: center;
}

.card {
  background: #ffffff;
  padding: 40px 30px;
  border-radius: 20px;
  width: 100%;
  max-width: 450px;
  box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1);
}

h2 {
  font-size: 26px;
  color: #1a1a1a;
  margin-bottom: 5px;
  text-align: left;
}

.subtitle {
  color: #777;
  font-size: 14px;
  margin-bottom: 25px;
  text-align: left;
}

.input-group {
  margin-bottom: 15px;
  flex: 1;
}

.row {
  display: flex;
  gap: 10px;
}

input[type="text"],
input[type="email"],
input[type="tel"],
input[type="password"] {
  width: 100%;
  padding: 14px 18px;
  border: 1px solid #ddd;
  border-radius: 12px;
  font-size: 15px;
  outline: none;
  transition: border-color 0.3s;
}

input:focus {
  border-color: #667eea;
}

.terms-container {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  margin: 15px 0 20px 0;
  font-size: 13px;
  color: #333;
}

.terms-container input {
  margin-top: 3px;
  width: 16px;
  height: 16px;
  cursor: pointer;
}

.terms-container label {
  line-height: 1.4;
}

.btn-primary {
  width: 100%;
  padding: 15px;
  border: none;
  border-radius: 25px;
  background: linear-gradient(to right, #667eea, #764ba2);
  color: white;
  font-size: 16px;
  font-weight: 600;
  cursor: pointer;
  transition: opacity 0.3s;
}

.btn-primary:hover {
  opacity: 0.9;
}

.divider {
  text-align: center;
  margin: 25px 0;
  position: relative;
}

.divider span {
  background: #fff;
  padding: 0 10px;
  color: #999;
  font-size: 14px;
  position: relative;
  z-index: 1;
}

.divider::before {
  content: "";
  position: absolute;
  top: 50%;
  left: 0;
  right: 0;
  height: 1px;
  background: #eee;
  z-index: 0;
}

.social-buttons {
  display: flex;
  gap: 15px;
  margin-bottom: 25px;
}

.btn-social {
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  padding: 12px;
  border-radius: 12px;
  text-decoration: none;
  font-size: 14px;
  font-weight: 600;
  border: 1px solid #ddd;
  transition: background 0.3s;
}

.btn-social.google {
  background: #fff;
  color: #333;
}

.btn-social.github {
  background: #24292e;
  color: #fff;
  border-color: #24292e;
}

.btn-social:hover {
  opacity: 0.9;
}

.footer-text {
  text-align: center;
  font-size: 14px;
  color: #666;
}

.footer-text a {
  color: #667eea;
  text-decoration: none;
  font-weight: 600;
}

.footer-text a:hover {
  text-decoration: underline;
}

@media (max-width: 400px) {
  .row {
    flex-direction: column;
    gap: 15px;
  }
  .card {
    padding: 30px 20px;
  }
}
`;

// Route to serve the embedded CSS
app.get('/style.css', (req, res) => {
  res.setHeader('Content-Type', 'text/css');
  res.send(cssStyles);
});

// Serve static files from 'public' folder (for index.html and script.js)
app.use(express.static(path.join(__dirname, 'public')));

// Session Setup
app.use(session({
  secret: process.env.SESSION_SECRET || 'fallback_secret',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ 
    mongoUrl: process.env.MONGO_URI,
    collectionName: 'sessions'
  }),
  cookie: { 
    maxAge: 24 * 60 * 60 * 1000, 
    secure: process.env.NODE_ENV === 'production' 
  }
}));

app.use(passport.initialize());
app.use(passport.session());

// --- MONGODB CONNECTION ---
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB Connected'))
  .catch(err => console.error('MongoDB Connection Error:', err));

// --- USER MODEL ---
const userSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  phone: { type: String, required: true },
  password: { type: String },
  googleId: { type: String },
  githubId: { type: String }
});

userSchema.pre('save', async function (next) {
  if (!this.isModified('password') || !this.password) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

userSchema.methods.comparePassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

const User = mongoose.model('User', userSchema);

// --- PASSPORT CONFIGURATION ---
passport.use(new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
  try {
    const user = await User.findOne({ email });
    if (!user) return done(null, false, { message: 'User not found' });
    if (!user.password) return done(null, false, { message: 'Please login via Google or GitHub' });
    
    const isMatch = await user.comparePassword(password);
    if (isMatch) return done(null, user);
    return done(null, false, { message: 'Incorrect password' });
  } catch (err) {
    return done(err);
  }
}));

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "/auth/google/callback",
  proxy: true 
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let user = await User.findOne({ googleId: profile.id });
    if (user) return done(null, user);

    const newUser = new User({
      googleId: profile.id,
      firstName: profile.name.givenName || 'Google',
      lastName: profile.name.familyName || 'User',
      email: profile.emails[0].value,
      phone: 'Not Provided'
    });
    await newUser.save();
    done(null, newUser);
  } catch (err) {
    done(err, null);
  }
}));

passport.use(new GitHubStrategy({
  clientID: process.env.GITHUB_CLIENT_ID,
  clientSecret: process.env.GITHUB_CLIENT_SECRET,
  callbackURL: "/auth/github/callback",
  proxy: true 
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let user = await User.findOne({ githubId: profile.id });
    if (user) return done(null, user);

    const newUser = new User({
      githubId: profile.id,
      firstName: profile.displayName || profile.username || 'GitHub',
      lastName: 'User',
      email: profile.emails ? profile.emails[0].value : `${profile.username}@github.com`,
      phone: 'Not Provided'
    });
    await newUser.save();
    done(null, newUser);
  } catch (err) {
    done(err, null);
  }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// --- ROUTES ---
app.post('/api/register', async (req, res) => {
  const { firstName, lastName, email, phone, password } = req.body;
  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: 'Email already exists' });

    const newUser = new User({ firstName, lastName, email, phone, password });
    await newUser.save();
    
    req.login(newUser, (err) => {
      if (err) return res.status(500).json({ message: 'Error logging in' });
      return res.status(201).json({ message: 'User registered successfully', user: newUser });
    });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => { res.redirect('/dashboard.html'); }
);

app.get('/auth/github', passport.authenticate('github', { scope: ['user:email'] }));
app.get('/auth/github/callback', 
  passport.authenticate('github', { failureRedirect: '/' }),
  (req, res) => { res.redirect('/dashboard.html'); }
);

app.get('/api/logout', (req, res) => {
  req.logout((err) => {
    if (err) return res.status(500).json({ message: 'Error logging out' });
    res.redirect('/');
  });
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
