const express = require('express');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 9001;
const SECRET_KEY = 'segarikan-secret-key';

// Setup CORS
const allowedOrigins = [
  'http://localhost:9000',
  'https://segarikan.vercel.app',
];
app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
  })
);

app.options(
  '*',
  cors({
    origin: allowedOrigins,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
  })
);

app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Setup multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(__dirname, 'uploads');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  },
});
const upload = multer({ storage });

// Simulasi database sementara
let users = [];
let stories = [];

// Middleware JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token)
    return res.status(401).json({ error: true, message: 'Token required' });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err)
      return res.status(403).json({ error: true, message: 'Invalid token' });
    req.user = user;
    next();
  });
}

// ======= ROUTES =======

// REGISTER
app.post('/v1/register', (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res
      .status(400)
      .json({ error: true, message: 'Name, email and password are required' });
  }
  if (users.find((u) => u.email === email)) {
    return res
      .status(400)
      .json({ error: true, message: 'Email already exists' });
  }
  const user = { id: Date.now().toString(), name, email, password };
  users.push(user);
  res.json({ error: false, message: 'User created successfully' });
});

// LOGIN
app.post('/v1/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res
      .status(400)
      .json({ error: true, message: 'Email and password are required' });
  }
  const user = users.find((u) => u.email === email && u.password === password);
  if (!user)
    return res
      .status(401)
      .json({ error: true, message: 'Invalid credentials' });

  const token = jwt.sign({ userId: user.id, name: user.name }, SECRET_KEY, {
    expiresIn: '2h',
  });
  res.json({
    error: false,
    message: 'Login successful',
    loginResult: { userId: user.id, name: user.name, token },
  });
});

// TAMBAH CERITA (AUTH)
app.post(
  '/v1/stories',
  authenticateToken,
  upload.single('photo'),
  (req, res) => {
    const { description, lat, lon } = req.body;
    if (!req.file) {
      return res
        .status(400)
        .json({ error: true, message: 'Photo upload required' });
    }

    const photoUrl = `${req.protocol}://${req.get('host')}/uploads/${
      req.file.filename
    }`;
    const story = {
      id: 'story-' + Date.now(),
      name: req.user.name,
      description: description || '',
      photoUrl,
      createdAt: new Date(),
      lat: lat ? parseFloat(lat) : null,
      lon: lon ? parseFloat(lon) : null,
    };
    stories.push(story);
    res.json({ error: false, message: 'Story added successfully', story });
  }
);

// TAMBAH CERITA (GUEST)
app.post('/v1/stories/guest', upload.single('photo'), (req, res) => {
  const { description, lat, lon } = req.body;
  if (!req.file) {
    return res
      .status(400)
      .json({ error: true, message: 'Photo upload required' });
  }

  const photoUrl = `${req.protocol}://${req.get('host')}/uploads/${
    req.file.filename
  }`;
  const story = {
    id: 'story-' + Date.now(),
    name: 'Guest',
    description: description || '',
    photoUrl,
    createdAt: new Date(),
    lat: lat ? parseFloat(lat) : null,
    lon: lon ? parseFloat(lon) : null,
  };
  stories.push(story);
  res.json({ error: false, message: 'Story added successfully', story });
});

// AMBIL SEMUA CERITA
app.get('/v1/stories', authenticateToken, (req, res) => {
  const { location } = req.query;
  let listStory = stories;
  if (location === '1') {
    listStory = stories.filter((s) => s.lat !== null && s.lon !== null);
  }
  res.json({
    error: false,
    message: 'Stories fetched successfully',
    listStory,
  });
});

// AMBIL DETAIL CERITA
app.get('/v1/stories/:id', authenticateToken, (req, res) => {
  const story = stories.find((s) => s.id === req.params.id);
  if (!story)
    return res.status(404).json({ error: true, message: 'Story not found' });
  res.json({ error: false, message: 'Story fetched successfully', story });
});

// AMBIL RIWAYAT CERITA USER
app.get('/v1/history', authenticateToken, (req, res) => {
  const userStories = stories.filter((s) => s.name === req.user.name);
  res.json({
    error: false,
    message: 'User story history fetched successfully',
    history: userStories,
  });
});

// RUN SERVER
app.listen(PORT, () => {
  console.log(`SegarIkan API running on port ${PORT}`);
});
