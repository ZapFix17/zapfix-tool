import express from 'express';
import mongoose from 'mongoose';
import multer from 'multer';
import { v2 as cloudinary } from 'cloudinary';
import bcryptjs from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const PORT = process.env.PORT || 10000;  // Render uses PORT env

// Middleware
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));
app.use(express.static(join(__dirname, 'public')));  // Correct path: src/public

app.use(cors({
  origin: [
    'https://zapfix-tools.onrender.com',
    'http://localhost:3000',
    'http://localhost:5173'
  ],
  credentials: true
}));

// Rate limiting for uploads
const uploadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 mins
  max: 10,
  message: { error: 'Too many uploads, try again later' }
});

// Cloudinary config
cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Multer: Memory storage
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: 100 * 1024 * 1024 }, // 100MB
  fileFilter: (req, file, cb) => {
    const allowed = [
      'image/jpeg', 'image/png', 'image/gif',
      'application/octet-stream', 'application/zip',
      'application/x-rar-compressed', 'application/x-7z-compressed'
    ];
    cb(null, allowed.includes(file.mimetype));
  }
});

// MongoDB
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB Connected'))
  .catch(err => console.error('MongoDB Error:', err));

// Tool Schema
const toolSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, required: true },
  icon: { type: String, required: true },
  thumbnail: { type: String, required: true },
  file: { type: String, required: true },
  likes: { type: Number, default: 0 },
  comments: [{
    name: String,
    text: String,
    createdAt: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now }
});

const Tool = mongoose.model('Tool', toolSchema);

// JWT Middleware
const verifyJWT = (req, res, next) => {
  const authHeader = req.header('Authorization');
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }
  const token = authHeader.split(' ')[1];
  try {
    jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// ========================
// PUBLIC API
// ========================

app.get('/api/tools', async (req, res) => {
  try {
    const tools = await Tool.find().sort({ createdAt: -1 });
    res.json(tools);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch tools' });
  }
});

app.get('/api/tools/:id', async (req, res) => {
  try {
    const tool = await Tool.findById(req.params.id);
    if (!tool) return res.status(404).json({ error: 'Tool not found' });
    res.json(tool);
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/tools/:id/like', async (req, res) => {
  try {
    const tool = await Tool.findByIdAndUpdate(
      req.params.id,
      { $inc: { likes: 1 } },
      { new: true }
    );
    if (!tool) return res.status(404).json({ error: 'Tool not found' });
    res.json({ likes: tool.likes });
  } catch {
    res.status(500).json({ error: 'Failed to like' });
  }
});

app.post('/api/tools/:id/comments', async (req, res) => {
  try {
    const { name, text } = req.body;
    if (!text?.trim()) return res.status(400).json({ error: 'Text required' });

    const tool = await Tool.findByIdAndUpdate(
      req.params.id,
      { $push: { comments: { name: name || 'Anonymous', text } } },
      { new: true }
    );
    if (!tool) return res.status(404).json({ error: 'Tool not found' });
    res.json(tool.comments);
  } catch {
    res.status(500).json({ error: 'Failed to comment' });
  }
});

// ========================
// ADMIN API
// ========================

app.post('/api/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (email !== process.env.ADMIN_EMAIL) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const match = await bcryptjs.compare(password, process.env.ADMIN_HASH);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '24h' });
    res.json({ token });
  } catch {
    res.status(500).json({ error: 'Login failed' });
  }
});

app.post('/api/admin/upload', verifyJWT, uploadLimiter, upload.fields([
  { name: 'icon', maxCount: 1 },
  { name: 'thumbnail', maxCount: 1 },
  { name: 'file', maxCount: 1 }
]), async (req, res) => {
  try {
    const { name, description } = req.body;
    if (!name || !description || !req.files?.icon || !req.files?.thumbnail || !req.files?.file) {
      return res.status(400).json({ error: 'All fields required' });
    }

    const uploadFile = (buffer, type = 'raw') => {
      return new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream(
          { folder: 'zapfix_tools', resource_type: type },
          (err, result) => err ? reject(err) : resolve(result.secure_url)
        );
        stream.end(buffer);
      });
    };

    const [icon, thumb, file] = await Promise.all([
      uploadFile(req.files.icon[0].buffer, 'image'),
      uploadFile(req.files.thumbnail[0].buffer, 'image'),
      uploadFile(req.files.file[0].buffer, 'raw')
    ]);

    const tool = await Tool.create({ name, description, icon, thumbnail: thumb, file });
    res.json({ message: 'Uploaded', tool });
  } catch (err) {
    res.status(500).json({ error: 'Upload failed' });
  }
});

app.get('/api/admin/tools', verifyJWT, async (req, res) => {
  try {
    const tools = await Tool.find().sort({ createdAt: -1 });
    res.json(tools);
  } catch {
    res.status(500).json({ error: 'Failed to fetch' });
  }
});

app.put('/api/admin/tool/:id', verifyJWT, upload.fields([
  { name: 'icon', maxCount: 1 },
  { name: 'thumbnail', maxCount: 1 },
  { name: 'file', maxCount: 1 }
]), async (req, res) => {
  try {
    const updates = {};
    if (req.body.name) updates.name = req.body.name;
    if (req.body.description) updates.description = req.body.description;

    const uploadFile = (buffer, type = 'raw') => {
      return new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream(
          { folder: 'zapfix_tools', resource_type: type },
          (err, result) => err ? reject(err) : resolve(result.secure_url)
        );
        stream.end(buffer);
      });
    };

    if (req.files?.icon) updates.icon = await uploadFile(req.files.icon[0].buffer, 'image');
    if (req.files?.thumbnail) updates.thumbnail = await uploadFile(req.files.thumbnail[0].buffer, 'image');
    if (req.files?.file) updates.file = await uploadFile(req.files.file[0].buffer, 'raw');

    const tool = await Tool.findByIdAndUpdate(req.params.id, updates, { new: true });
    if (!tool) return res.status(404).json({ error: 'Not found' });
    res.json({ message: 'Updated', tool });
  } catch {
    res.status(500).json({ error: 'Update failed' });
  }
});

app.delete('/api/admin/tool/:id', verifyJWT, async (req, res) => {
  try {
    const tool = await Tool.findByIdAndDelete(req.params.id);
    if (!tool) return res.status(404).json({ error: 'Not found' });
    res.json({ message: 'Deleted' });
  } catch {
    res.status(500).json({ error: 'Delete failed' });
  }
});

app.delete('/api/admin/tool/:toolId/comment/:commentId', verifyJWT, async (req, res) => {
  try {
    const tool = await Tool.findByIdAndUpdate(
      req.params.toolId,
      { $pull: { comments: { _id: req.params.commentId } } },
      { new: true }
    );
    if (!tool) return res.status(404).json({ error: 'Not found' });
    res.json({ message: 'Comment deleted', comments: tool.comments });
  } catch {
    res.status(500).json({ error: 'Delete failed' });
  }
});

// Serve index.html for root
app.get('/', (req, res) => {
  res.sendFile(join(__dirname, 'public', 'index.html'));
});

// Start
app.listen(PORT, () => {
  console.log(`ZAPFIX Tools LIVE on port ${PORT}`);
  console.log(`Visit: https://your-app.onrender.com`);
});
