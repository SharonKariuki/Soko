// ===============================
// IMPORTS & SETUP
// ===============================
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require("path");
const jwt = require('jsonwebtoken');
require('dotenv').config();
const baseUrl = process.env.BASE_URL || "http://localhost:5000";


const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(express.json());
app.use(cors({
 origin: "*",
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ===============================
// MONGODB CONNECTION
// ===============================
if (!process.env.MONGO_URL) {
  console.error("❌ MONGO_URL is not defined in environment variables.");
  process.exit(1);
}

mongoose.connect(process.env.MONGO_URL, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log("✅ Connected to MongoDB Atlas"))
.catch((error) => {
  console.error("❌ MongoDB connection error:", error.message);
  process.exit(1);
});


// ===============================
// SCHEMAS & MODELS
// ===============================
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  role: { type: String, default: "buyer" }
});
const User = mongoose.model("User", userSchema);

const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  price: { type: Number, required: true },
  description: String,
  image: String,
  category: String,
  discount: { type: Number, default: 0 },
  featured: { type: Boolean, default: false },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" }
});
const Product = mongoose.model("Product", productSchema);

const cartSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  products: [{
    product: { type: mongoose.Schema.Types.ObjectId, ref: "Product" },
    quantity: Number
  }]
});
const Cart = mongoose.model("Cart", cartSchema);

const orderSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  items: [{
    product: { type: mongoose.Schema.Types.ObjectId, ref: "Product" },
    quantity: Number
  }],
  createdAt: { type: Date, default: Date.now }
});
const Order = mongoose.model("Order", orderSchema);

const bannerSchema = new mongoose.Schema({
  image: {type: String, required: true},
  title: String,
  subtitle: String,
  link: String,
  active: { type: Boolean, default: true },
  order: { type: Number, default: 0 }
});
const Banner = mongoose.model("Banner", bannerSchema);

// ===============================
// AUTHENTICATION MIDDLEWARE
// ===============================
const auth = (req, res, next) => {
  const token = req.header('Authorization')?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "No token provided" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "secret123");
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ message: "Invalid token" });
  }
};

// ===============================
// AUTH ROUTES
// ===============================
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ message: "Name, email and password are required" });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: "Email already registered" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashedPassword, role });
    await user.save();
    res.status(201).json({ message: "User registered successfully!" });
  } catch (error) {
    console.error("Register error:", error);
    res.status(400).json({ message: "Error registering user", error: error.message });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "Email and password required" });

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "User not found" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Incorrect password" });

    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET || "secret123",
      { expiresIn: "1h" }
    );

    res.json({ token });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Login failed", error: error.message });
  }
});

// ===============================
// PRODUCT ROUTES
// ===============================
app.get('/api/products', async (req, res) => {
  try {
    const products = await Product.find().populate("createdBy", "name");
    res.json(products);
  } catch (error) {
    console.error("Get products error:", error);
    res.status(500).json({ message: "Error getting products" });
  }
});

app.get('/api/products/featured', async (req, res) => {
  try {
    const featuredProducts = await Product.find({ featured: true }).limit(8);
    res.json(featuredProducts);
  } catch (error) {
    console.error("Error fetching featured products:", error);
    res.status(500).json({ message: "Error fetching featured products" });
  }
});

app.post("/api/products", auth, async (req, res) => {
  try {
    if (!["admin", "poster"].includes(req.user.role)) {
      return res.status(403).json({ message: "Not authorized" });
    }

    const { name, price, description, image, category, discount, featured } = req.body;
    if (!name || price === undefined) return res.status(400).json({ message: "Name and price are required" });
    const isFeatured = featured === true || featured === "true" || featured === 1 || featured === "1";

    const product = new Product({
      name,
      price,
      description,
      image,
      category,
      discount: discount || 0,
      featured: isFeatured,
      createdBy: req.user.id
    });

    const savedProduct = await product.save();
    res.status(201).json(savedProduct);
  } catch (error) {
    console.error("Add product error:", error);
    res.status(500).json({ message: "Error adding product", error: error.message });
  }
});

app.put("/api/products/:id/featured", auth, async (req, res) => {
  try {
    if (!["admin", "poster"].includes(req.user.role)) {
      return res.status(403).json({ message: "Not authorized" });
    }

    const { featured } = req.body;
    if (typeof featured !== "boolean") {
      return res.status(400).json({ message: "featured field must be boolean" });
    }

    const product = await Product.findByIdAndUpdate(
      req.params.id,
      { featured },
      { new: true }
    );

    if (!product) return res.status(404).json({ message: "Product not found" });

    res.json(product);
  } catch (error) {
    console.error("Set featured product error:", error);
    res.status(500).json({ message: "Error updating featured status", error: error.message });
  }
});

app.delete("/api/products/:id", auth, async (req, res) => {
  try {
    if (!["admin", "poster"].includes(req.user.role)) {
      return res.status(403).json({ message: "Not authorized" });
    }

    const deletedProduct = await Product.findByIdAndDelete(req.params.id);
    if (!deletedProduct) return res.status(404).json({ message: "Product not found" });

    res.json({ message: "Product deleted successfully" });
  } catch (error) {
    console.error("Delete product error:", error);
    res.status(500).json({ message: "Error deleting product", error: error.message });
  }
});

// ===============================
// IMAGE UPLOAD
// ===============================
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/");
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname);
    cb(null, `${Date.now()}${ext}`);
  }
});
const upload = multer({ storage });

app.post("/api/upload", auth, upload.single("image"), (req, res) => {
  if (!req.file) return res.status(400).json({ message: "No file uploaded" });

  const imageUrl = `${req.protocol}://${req.get("host")}/uploads/${req.file.filename}`;
  res.json({ imageUrl });
});

// ===============================
// CART ROUTES
// ===============================
app.post("/api/cart", auth, async (req, res) => {
  try {
    const { productId, quantity } = req.body;
    if (!productId || !quantity || quantity <= 0) {
      return res.status(400).json({ message: "Valid productId and quantity are required" });
    }

    let cart = await Cart.findOne({ user: req.user.id });
    if (!cart) {
      cart = new Cart({ user: req.user.id, products: [{ product: productId, quantity }] });
    } else {
      const index = cart.products.findIndex(p => p.product.toString() === productId);
      if (index > -1) {
        cart.products[index].quantity += quantity;
      } else {
        cart.products.push({ product: productId, quantity });
      }
    }

    await cart.save();
    res.json(cart);
  } catch (error) {
    console.error("Add to cart error:", error);
    res.status(500).json({ message: "Error adding to cart", error: error.message });
  }
});

app.get("/api/cart", auth, async (req, res) => {
  try {
    const cart = await Cart.findOne({ user: req.user.id }).populate("products.product");
    if (!cart) return res.json({ products: [] });
    res.json(cart);
  } catch (error) {
    console.error("Get cart error:", error);
    res.status(500).json({ message: "Error fetching cart", error: error.message });
  }
});

app.delete("/api/cart/:productId", auth, async (req, res) => {
  try {
    const cart = await Cart.findOne({ user: req.user.id });
    if (!cart) return res.status(404).json({ message: "Cart not found" });

    cart.products = cart.products.filter(p => p.product.toString() !== req.params.productId);
    await cart.save();
    res.json(cart);
  } catch (error) {
    console.error("Remove from cart error:", error);
    res.status(500).json({ message: "Error removing item", error: error.message });
  }
});

// ===============================
// BANNER ROUTE (FIXED)
// ===============================
app.get("/api/banner", async (req, res) => {
  try {
    const banner = await Banner.findOne({ active: true }).sort({ order: 1 });
    if (!banner) return res.status(404).json({ message: "No active banner found" });
    res.json(banner);
  } catch (error) {
    console.error("Error fetching banner:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.post("/api/banner", auth, async (req, res) => {
  try {
    // Only allow admin or poster roles to add banners
    if (!["admin", "poster"].includes(req.user.role)) {
      return res.status(403).json({ message: "Not authorized" });
    }

    const { image, title, subtitle, link, active, order } = req.body;
    if (!image) return res.status(400).json({ message: "Image is required" });

    const banner = new Banner({
      image,
      title,
      subtitle,
      link,
      active: active !== undefined ? active : true,
      order: order || 0,
    });

    await banner.save();
    res.status(201).json(banner);
  } catch (error) {
    console.error("Create banner error:", error);
    res.status(500).json({ message: "Error creating banner", error: error.message });
  }
});

// ===============================
// ORDER ROUTES
// ===============================
app.post("/api/orders", auth, async (req, res) => {
  try {
    const cart = await Cart.findOne({ user: req.user.id });
    if (!cart || cart.products.length === 0) {
      return res.status(400).json({ message: "Cart is empty" });
    }

    const order = new Order({
      user: req.user.id,
      items: cart.products.map(p => ({
        product: p.product,
        quantity: p.quantity
      }))
    });

    await order.save();
    cart.products = [];
    await cart.save();

    res.status(201).json(order);
  } catch (error) {
    console.error("Create order error:", error);
    res.status(500).json({ message: "Error creating order", error: error.message });
  }
});

app.get("/api/orders", auth, async (req, res) => {
  try {
    const orders = await Order.find({ user: req.user.id }).populate("items.product");
    res.json(orders);
  } catch (error) {
    console.error("Get orders error:", error);
    res.status(500).json({ message: "Error fetching orders", error: error.message });
  }
});

// ===============================
// START SERVER
// ===============================
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});

