# 🛍️ Product Management Dashboard

## 🌐 Live Demo  

🚀 **Try the App Here:**  
👉 https://product-dashboard-mu-one.vercel.app/login  

Explore features like:  
- Secure Login (Admin/User)  
- Product Dashboard  
- CRUD Operations (Admin)  
- Responsive UI & Animations  

---

## 📌 Overview  
This project is a **Full Stack Product Management Dashboard** designed to manage products efficiently with secure authentication and role-based access control.  

The system allows **Admin users** to perform full CRUD operations, while **normal users** can only view products. It integrates a modern **React frontend** with a secure **Node.js backend**.

---

## ✨ Key Features  

### 🔐 Authentication System  
- JWT-based secure login system  
- Role-Based Access Control (Admin & User)  
- Protected routes for secure access  

### 👨‍💼 Admin Control  
- Add new products  
- Edit product details  
- Delete products  
- Full access dashboard  

### 👤 User Access  
- View product list  
- Restricted actions (no edit/delete)  

### 📊 Dashboard Functionalities  
- Real-time inventory statistics  
- Instant search & filtering  
- Clean and responsive UI  
- Error handling & loading states  

### 🎨 UI & Experience  
- Dark/Light theme persistence  
- Glassmorphism modern UI design  
- Smooth animations using Framer Motion  

---

## 🧱 Tech Stack  

### 🌐 client 
- React 19  
- Vite  
- Framer Motion  
- Lucide Icons  

### 🔧 server
- Node.js  
- Express.js  
- JWT (Authentication)  
- BcryptJS (Password Hashing)  

### 🗄️ Database  
- MongoDB (Mongoose ODM)  

### 🎨 Styling  
- Vanilla CSS (Custom Design System)  

---

## 📂 Project Structure  

- client/  
  - src/  
    - components/  
    - pages/  
    - App.jsx  
  - public/  

- server/  
  - routes/  
  - controllers/  
  - models/  
  - middleware/  
  - server.js  

- README.md  

---
2️⃣ server Setup
cd server
npm install
npm start
---
3️⃣ client Setup
cd client
npm install
npm run dev
---

🔑 API Endpoints
Method	Endpoint	Access	Description
POST	/login	Public	User login
GET	/products	Admin/User	Get products
POST	/products	Admin	Add product
PUT	/products/:id	Admin	Update product
DELETE	/products/:id	Admin	Delete product

---

👤 Sample Users

Admin:

Username: admin
Password: admin123

User:

Username: user
Password: user123

---

🚀 Future Improvements
Pagination & advanced filtering
Unit testing
Deployment (Vercel + Render)
Performance optimization
UI enhancements

---

👩‍💻 Developer

Muskan Pathan
B.Tech Computer Science & Engineering
Project: Product Management Dashboard
