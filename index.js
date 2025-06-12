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

app.use(express.json({ limit: '10mb' })); // Increased for base64 images
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
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
});

// Simulasi database sementara
let users = [];
let stories = [];
let predictions = []; // New: for fish freshness predictions

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

// ======= ORIGINAL ROUTES =======

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'OK',
    message: 'SegarIkan API with IndexedDB is running',
    timestamp: new Date().toISOString(),
  });
});

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

// ======= NEW INDEXEDDB FEATURES =======

// Fish Prediction (supports both file upload and base64)
app.post(
  '/api/predictions',
  authenticateToken,
  upload.single('image'),
  (req, res) => {
    try {
      const {
        imageData,
        predictionId,
        fishType,
        notes,
        prediction,
        confidence,
      } = req.body;

      // Validate required fields
      if (!prediction || !confidence) {
        return res.status(400).json({
          error: true,
          message: 'Prediction and confidence are required',
        });
      }

      // Generate prediction ID if not provided
      const finalPredictionId =
        predictionId ||
        Date.now().toString() + Math.random().toString(36).substr(2, 9);

      let imagePath = null;
      let finalImageData = imageData;

      // Handle file upload
      if (req.file) {
        imagePath = req.file.path;
        // Convert uploaded file to base64 for IndexedDB compatibility
        const imageBuffer = fs.readFileSync(req.file.path);
        finalImageData = `data:${
          req.file.mimetype
        };base64,${imageBuffer.toString('base64')}`;
      }

      // Save to in-memory array (server backup)
      const newPrediction = {
        id: finalPredictionId,
        userId: req.user.userId,
        userName: req.user.name,
        imageData: finalImageData,
        imagePath: imagePath,
        prediction: prediction,
        confidence: parseFloat(confidence),
        fishType: fishType || 'unknown',
        notes: notes || '',
        createdAt: new Date().toISOString(),
        syncStatus: 'synced',
      };

      predictions.push(newPrediction);

      // Return data formatted for IndexedDB
      res.status(201).json({
        error: false,
        message: 'Prediction completed successfully',
        prediction: newPrediction,
      });
    } catch (error) {
      res.status(500).json({ error: true, message: error.message });
    }
  }
);

// Sync predictions from IndexedDB to server
app.post('/api/predictions/sync', authenticateToken, (req, res) => {
  try {
    const { predictions: clientPredictions } = req.body;

    if (!Array.isArray(clientPredictions)) {
      return res
        .status(400)
        .json({ error: true, message: 'Predictions must be an array' });
    }

    const syncResults = [];

    for (const pred of clientPredictions) {
      try {
        // Check if prediction already exists
        const existingPrediction = predictions.find(
          (p) => p.id === pred.id && p.userId === req.user.userId
        );

        if (!existingPrediction) {
          const newPrediction = {
            id: pred.id,
            userId: req.user.userId,
            userName: req.user.name,
            imageData: pred.imageData,
            prediction: pred.prediction,
            confidence: pred.confidence,
            fishType: pred.fishType,
            notes: pred.notes,
            createdAt: pred.createdAt,
            syncStatus: 'synced',
          };

          predictions.push(newPrediction);
          syncResults.push({ id: pred.id, status: 'synced' });
        } else {
          syncResults.push({ id: pred.id, status: 'already_exists' });
        }
      } catch (error) {
        syncResults.push({
          id: pred.id,
          status: 'error',
          error: error.message,
        });
      }
    }

    res.json({
      error: false,
      message: 'Sync completed',
      results: syncResults,
    });
  } catch (error) {
    res.status(500).json({ error: true, message: error.message });
  }
});

// Get user's predictions from server (for sync/backup)
app.get('/api/predictions/server', authenticateToken, (req, res) => {
  try {
    const userPredictions = predictions
      .filter((p) => p.userId === req.user.userId)
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    res.json({
      error: false,
      message: 'Predictions fetched successfully',
      predictions: userPredictions,
    });
  } catch (error) {
    res.status(500).json({ error: true, message: error.message });
  }
});

// Statistics endpoint
app.get('/api/stats', authenticateToken, (req, res) => {
  try {
    const userPredictions = predictions.filter(
      (p) => p.userId === req.user.userId
    );

    const totalPredictions = userPredictions.length;
    const freshCount = userPredictions.filter(
      (p) => p.prediction === 'fresh'
    ).length;
    const notFreshCount = userPredictions.filter(
      (p) => p.prediction === 'not_fresh'
    ).length;

    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    const recentPredictions = userPredictions.filter(
      (p) => new Date(p.createdAt) >= sevenDaysAgo
    ).length;

    res.json({
      error: false,
      message: 'Stats fetched successfully',
      stats: {
        totalPredictions,
        freshCount,
        notFreshCount,
        recentPredictions,
        freshPercentage:
          totalPredictions > 0
            ? ((freshCount / totalPredictions) * 100).toFixed(1)
            : 0,
      },
    });
  } catch (error) {
    res.status(500).json({ error: true, message: error.message });
  }
});

// Serve IndexedDB client utilities
app.get('/api/client/indexeddb-utils.js', (req, res) => {
  res.setHeader('Content-Type', 'application/javascript');
  res.send(`
// IndexedDB Utilities for SegarIkan App
class SegarIkanDB {
    constructor() {
        this.dbName = 'SegarIkanDB';
        this.dbVersion = 1;
        this.db = null;
    }

    async init(userId) {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open(this.dbName + '_' + userId, this.dbVersion);
            
            request.onerror = () => reject(request.error);
            request.onsuccess = () => {
                this.db = request.result;
                resolve(this.db);
            };
            
            request.onupgradeneeded = (event) => {
                const db = event.target.result;
                
                // Create predictions store
                if (!db.objectStoreNames.contains('predictions')) {
                    const predictionsStore = db.createObjectStore('predictions', { keyPath: 'id' });
                    predictionsStore.createIndex('userId', 'userId', { unique: false });
                    predictionsStore.createIndex('createdAt', 'createdAt', { unique: false });
                    predictionsStore.createIndex('prediction', 'prediction', { unique: false });
                }
                
                // Create stories store (for offline support)
                if (!db.objectStoreNames.contains('stories')) {
                    const storiesStore = db.createObjectStore('stories', { keyPath: 'id' });
                    storiesStore.createIndex('name', 'name', { unique: false });
                    storiesStore.createIndex('createdAt', 'createdAt', { unique: false });
                }
                
                // Create settings store
                if (!db.objectStoreNames.contains('settings')) {
                    db.createObjectStore('settings', { keyPath: 'key' });
                }
            };
        });
    }

    async savePrediction(prediction) {
        const transaction = this.db.transaction(['predictions'], 'readwrite');
        const store = transaction.objectStore('predictions');
        return store.put(prediction);
    }

    async getPredictions(userId) {
        const transaction = this.db.transaction(['predictions'], 'readonly');
        const store = transaction.objectStore('predictions');
        const index = store.index('userId');
        
        return new Promise((resolve, reject) => {
            const request = index.getAll(userId);
            request.onsuccess = () => {
                const predictions = request.result.sort((a, b) => 
                    new Date(b.createdAt) - new Date(a.createdAt)
                );
                resolve(predictions);
            };
            request.onerror = () => reject(request.error);
        });
    }

    async getPrediction(id) {
        const transaction = this.db.transaction(['predictions'], 'readonly');
        const store = transaction.objectStore('predictions');
        
        return new Promise((resolve, reject) => {
            const request = store.get(id);
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
    }

    async deletePrediction(id) {
        const transaction = this.db.transaction(['predictions'], 'readwrite');
        const store = transaction.objectStore('predictions');
        return store.delete(id);
    }

    async saveStory(story) {
        const transaction = this.db.transaction(['stories'], 'readwrite');
        const store = transaction.objectStore('stories');
        return store.put(story);
    }

    async getStories() {
        const transaction = this.db.transaction(['stories'], 'readonly');
        const store = transaction.objectStore('stories');
        
        return new Promise((resolve, reject) => {
            const request = store.getAll();
            request.onsuccess = () => {
                const stories = request.result.sort((a, b) => 
                    new Date(b.createdAt) - new Date(a.createdAt)
                );
                resolve(stories);
            };
            request.onerror = () => reject(request.error);
        });
    }

    async getStats(userId) {
        const predictions = await this.getPredictions(userId);
        const total = predictions.length;
        const fresh = predictions.filter(p => p.prediction === 'fresh').length;
        const notFresh = predictions.filter(p => p.prediction === 'not_fresh').length;
        
        // Recent predictions (last 7 days)
        const sevenDaysAgo = new Date();
        sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
        const recent = predictions.filter(p => new Date(p.createdAt) >= sevenDaysAgo).length;
        
        return {
            totalPredictions: total,
            freshCount: fresh,
            notFreshCount: notFresh,
            recentPredictions: recent,
            freshPercentage: total > 0 ? ((fresh / total) * 100).toFixed(1) : 0
        };
    }

    async saveSetting(key, value) {
        const transaction = this.db.transaction(['settings'], 'readwrite');
        const store = transaction.objectStore('settings');
        return store.put({ key, value });
    }

    async getSetting(key) {
        const transaction = this.db.transaction(['settings'], 'readonly');
        const store = transaction.objectStore('settings');
        
        return new Promise((resolve, reject) => {
            const request = store.get(key);
            request.onsuccess = () => resolve(request.result?.value);
            request.onerror = () => reject(request.error);
        });
    }

    async clearAll() {
        const transaction = this.db.transaction(['predictions', 'stories', 'settings'], 'readwrite');
        await transaction.objectStore('predictions').clear();
        await transaction.objectStore('stories').clear();
        await transaction.objectStore('settings').clear();
    }
}

// Export for use
window.SegarIkanDB = SegarIkanDB;
  `);
});

// Error handling middleware
app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res
        .status(400)
        .json({ error: true, message: 'File too large. Maximum size is 5MB.' });
    }
  }
  res.status(500).json({ error: true, message: error.message });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: true, message: 'Endpoint not found' });
});

// RUN SERVER
app.listen(PORT, () => {
  console.log(`SegarIkan API with IndexedDB running on port ${PORT}`);
  console.log(
    'IndexedDB utilities available at: /api/client/indexeddb-utils.js'
  );
});

module.exports = app;
