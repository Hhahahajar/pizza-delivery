const express = require('express');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const connectDB = require('./database');
const morgan = require('morgan');

const User = require('./models/User');
const Order = require('./models/Order');

const app = express();
const port = 3000;

// Connect to MongoDB
connectDB();

// Middleware setup
app.use(morgan('dev')); 
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 600000,
  },
}));

app.use(express.static(path.join(__dirname, 'public')));

// Set view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Passport middleware
app.use(passport.initialize());
app.use(passport.session());

// Passport Local Strategy for username/password login
passport.use(new LocalStrategy(
  async (username, password, done) => {
    try {
      const user = await User.findOne({ username });

      if (!user) {
        return done(null, false, { message: 'Incorrect username' });
      }

      const isMatch = await bcrypt.compare(password, user.password);

      if (!isMatch) {
        return done(null, false, { message: 'Incorrect password' });
      }

      return done(null, user);
    } catch (error) {
      return done(error);
    }
  }
));

// Serialize and deserialize user to maintain session
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (error) {
    done(error);
  }
});

// Middleware to check if user is logged in
function checkLogin(req, res, next) {
  if (req.isAuthenticated()) {
    // If user is logged in, proceed to the next middleware
    return next();
  } else {
    // If user is not logged in, redirect to the login page
    res.redirect('/login');
  }
}

// Routes
// Route for rendering the homepage after login
app.get('/dashboard', checkLogin, (req, res) => {
  res.render('dashboard', { user: req.user });
});

// Route for rendering the login page
app.get('/login', (req, res) => {
  res.render('login');
});

// Route for handling user login
app.post('/login', passport.authenticate('local', {
  successRedirect: '/dashboard',
  failureRedirect: '/login',
  failureFlash: true // Enable flash messages if needed
}));

// Route for serving the index.html file
app.get('/', (req, res) => {
  // Check if the user is logged in
  if (req.isAuthenticated()) {
    // If user is logged in, redirect to the dashboard
    res.render('dashboard', { user: req.user });
  } else {
    // If user is not logged in, serve the index.html file
    res.render('index');
  }
});

// Array to store order items temporarily
let orderItems = [];

// Route to add item to order
app.post('/add-to-order', checkLogin, (req, res) => {
  const { name, price } = req.body;
  orderItems.push({ name, price });
  res.json({ success: true });
});

// GET route for displaying the order form
app.get('/order', checkLogin, (req, res) => {
  // Calculate order total from session data or default to 0
  const orderItems = req.session.orderItems || [];
  const orderTotal = orderItems.reduce((total, item) => total + item.price * item.quantity, 0);
  res.render('order', { orderItems, orderTotal });
});

// POST route for confirming the order
app.post('/confirm-order', checkLogin, async (req, res) => {
  const { items } = req.body;

  try {
      // Calculate order total
      const orderTotal = items.reduce((total, item) => total + item.price * item.quantity, 0);

      // Save the order to MongoDB
      const newOrder = new Order({
          user: req.user._id,
          items,
          total: orderTotal
      });

      await newOrder.save();

      // Store order items and total in session (optional)
      req.session.orderItems = items;
      req.session.orderTotal = orderTotal;

      // Send order details as response data
      res.status(200).json({ success: true, username: req.user.username, orderItems: items, orderTotal });

  } catch (error) {
      console.error('Error saving order:', error);
      res.status(500).json({ success: false, message: 'Failed to save order' });
  }
});

// GET route for displaying the confirmation page
app.get('/confirmation', checkLogin, async (req, res) => {
  try {
      const orderItems = req.session.orderItems || [];
      const orderTotal = req.session.orderTotal || 0;

      res.render('confirmation', { username: req.user.username, orderItems, orderTotal });

  } catch (error) {
      console.error('Error fetching order:', error);
      res.status(500).send('Failed to fetch order');
  }
});

// Route for registering a new user
app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      username,
      email,
      password: hashedPassword
    });
    await user.save();
    res.status(201).send('User registered successfully');
  } catch (error) {
    console.error('Error registering user:', error);
    let errorMessage = 'Internal Server Error';

    if (error.name === 'MongoError' && error.code === 11000) {
      errorMessage = 'Username or email already exists';
      res.status(400).send(errorMessage);
    } else {
      res.status(500).send(errorMessage);
    }
  }
});

// Route for password recovery
app.get('/recovery', (req, res) => {
  res.render('recovery');
});

app.post('/recovery', async (req, res) => {
  const { username, newPassword, confirmPassword } = req.body;

  if (!username || !newPassword || !confirmPassword || newPassword !== confirmPassword) {
    return res.status(400).send('Invalid password recovery details');
  }

  try {
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(404).send('User not found');
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;

    await user.save();
    res.redirect('/login');
  } catch (err) {
    console.error('Password recovery error:', err);
    res.status(500).send('Internal server error');
  }
});

// Add a callback function to req.logout()
app.get('/logout', (req, res) => {
  req.logout((err) => {
      if (err) {
          console.error('Error logging out:', err);
          return next(err);
      }
      res.redirect('/'); // Redirect to home page after logout
  });
});

// Listen on port
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
