const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const mongoose = require('mongoose');

const bcrypt = require('bcryptjs');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const SECRET_KEY = process.env.JWT_SECRET || 'supersecretkey_change_me';
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/product_dashboard';

app.use(cors());
app.use(express.json());

// --- User Schema ---
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['admin', 'user'], default: 'user' }
});

const User = mongoose.model('User', userSchema);

// --- Product Schema ---
const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  price: { type: Number, required: true },
  category: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
}, {
  toJSON: { transform: (doc, ret) => { ret.id = ret._id; delete ret._id; delete ret.__v; } },
  toObject: { transform: (doc, ret) => { ret.id = ret._id; delete ret._id; delete ret.__v; } }
});

const Product = mongoose.model('Product', productSchema);

// --- MongoDB Connection & Seeding ---
mongoose.connect(MONGO_URI)
  .then(async () => {
    const dbHost = mongoose.connection.host;
    console.log(`✅ Connected to MongoDB at: ${dbHost}`);
    
    // Seed initial users if empty
    const userCount = await User.countDocuments();
    if (userCount === 0) {
      console.log('🌱 Seeding administrative and operational users...');
      const adminPassword = await bcrypt.hash('admin123', 10);
      const userPassword = await bcrypt.hash('user123', 10);
      const managerPassword = await bcrypt.hash('manager123', 10);
      const guestPassword = await bcrypt.hash('guest123', 10);
      
      await User.insertMany([
        { username: 'admin', password: adminPassword, role: 'admin' },
        { username: 'user', password: userPassword, role: 'user' },
        { username: 'manager', password: managerPassword, role: 'admin' },
        { username: 'tester', password: guestPassword, role: 'user' }
      ]);
      console.log('✅ User database initialized');
    }

    // Seed initial products if empty
    const productCount = await Product.countDocuments();
    if (productCount === 0) {
      console.log('🌱 Seeding rich product catalog...');
      const seededProducts = await Product.insertMany([
        { name: 'Ultra-Wide Curved Monitor', price: 899.99, category: 'Electronics' },
        { name: 'Mechanical RGB Keyboard', price: 159.50, category: 'Accessories' },
        { name: 'Ergonomic Mesh Chair', price: 349.00, category: 'Furniture' },
        { name: 'Wireless Noise Cancelling Headphones', price: 299.99, category: 'Electronics' },
        { name: 'Smart Home Hub v3', price: 129.00, category: 'Smart Home' },
        { name: '4K Mirrorless Camera', price: 1249.00, category: 'Electronics' },
        { name: 'Bamboo Standing Desk', price: 545.00, category: 'Furniture' },
        { name: 'Portable SSD 2TB', price: 189.00, category: 'Accessories' },
        { name: 'Acoustic Foam Panels (12pk)', price: 45.99, category: 'Studio' },
        { name: 'Professional Condenser Mic', price: 329.00, category: 'Studio' },
        { name: 'Smart LED Light Strip', price: 65.50, category: 'Smart Home' },
        { name: 'Thunderbolt 4 Dock', price: 249.00, category: 'Accessories' }
      ]);
      console.log(`✅ Product catalog initialized with ${seededProducts.length} items`);
    }
  })
  .catch(err => console.error('❌ MongoDB connection error:', err));

// --- Middleware ---

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ message: 'No token provided' });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ message: 'Token invalid or expired' });
    req.user = user;
    next();
  });
};

const authorizeRole = (role) => {
  return (req, res, next) => {
    if (req.user.role !== role) {
      return res.status(403).json({ message: 'Forbidden: Insufficient permissions' });
    }
    next();
  };
};

// --- Routes ---

// Login API
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  
  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ username: user.username, role: user.role }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token, role: user.role, username: user.username });
  } catch (err) {
    res.status(500).json({ message: 'Login error' });
  }
});

// GET /products (Admin & User)
app.get('/api/products', authenticateToken, async (req, res) => {
  try {
    const products = await Product.find().sort({ createdAt: -1 });
    res.json(products);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching products' });
  }
});

// GET /products/:id (Admin & User)
app.get('/api/products/:id', authenticateToken, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ message: 'Invalid product ID format' });
    }
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ message: 'Product not found' });
    res.json(product);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching product' });
  }
});

// POST /products (Admin only)
app.post('/api/products', authenticateToken, authorizeRole('admin'), async (req, res) => {
  const { name, price, category } = req.body;
  if (!name || !price || !category) {
    return res.status(400).json({ message: 'Missing product details' });
  }
  
  try {
    const newProduct = new Product({
      name,
      price: parseFloat(price),
      category
    });
    await newProduct.save();
    res.status(201).json(newProduct);
  } catch (err) {
    res.status(500).json({ message: 'Error creating product' });
  }
});

// PUT /products/:id (Admin only)
app.put('/api/products/:id', authenticateToken, authorizeRole('admin'), async (req, res) => {
  const { id } = req.params;
  const { name, price, category } = req.body;
  
  try {
    const updatedProduct = await Product.findByIdAndUpdate(
      id,
      { name, price: price ? parseFloat(price) : undefined, category },
      { new: true, runValidators: true }
    );

    if (!updatedProduct) return res.status(404).json({ message: 'Product not found' });
    res.json(updatedProduct);
  } catch (err) {
    res.status(500).json({ message: 'Error updating product' });
  }
});

// DELETE /products/:id (Admin only)
app.delete('/api/products/:id', authenticateToken, authorizeRole('admin'), async (req, res) => {
  const { id } = req.params;

  try {
    const deletedProduct = await Product.findByIdAndDelete(id);
    if (!deletedProduct) return res.status(404).json({ message: 'Product not found' });
    res.json({ message: 'Product deleted successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Error deleting product' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
