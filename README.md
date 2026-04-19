🛍️ Product Management Dashboard
📌 Overview

This project is a Full Stack Product Management Dashboard designed to manage products efficiently with secure authentication and role-based access control.

The system allows Admin users to perform full CRUD operations, while normal users can only view products. It integrates a modern React frontend with a secure Node.js backend.

✨ Key Features

🔐 Authentication System
JWT-based secure login system
Role-Based Access Control (Admin & User)
Protected routes for secure access

👨‍💼 Admin Control
Add new products
Edit product details
Delete products
Full access dashboard

👤 User Access
View product list
Restricted actions (no edit/delete)

📊 Dashboard Functionalities
Real-time inventory statistics
Instant search & filtering
Clean and responsive UI
Error handling & loading states

🎨 UI & Experience
Dark/Light theme persistence
Glassmorphism modern UI design
Smooth animations using Framer Motion

🧱 Tech Stack
🌐 Frontend
React 19
Vite
Framer Motion
Lucide Icons

🔧 Backend
Node.js
Express.js
JWT (Authentication)
BcryptJS (Password Hashing)

🗄️ Database
MongoDB (Mongoose ODM)
🎨 Styling
Vanilla CSS (Custom Design System)
📂 Project Structure
Product-Management-Dashboard
│
├── frontend
│   ├── src
│   │   ├── components
│   │   ├── pages
│   │   └── App.jsx
│
├── backend
│   ├── routes
│   ├── controllers
│   ├── middleware
│   ├── models
│   └── server.js
│
└── README.md

⚙️ Installation & Setup
1️⃣ Clone Repository
git clone https://github.com/your-username/product-dashboard.git
cd product-dashboard

2️⃣ Backend Setup
cd backend
npm install
npm start

3️⃣ Frontend Setup
cd frontend
npm install
npm run dev

🔑 API Endpoints
Method	Endpoint	Access	Description
POST	/login	Public	User login
GET	/products	Admin/User	Get products
POST	/products	Admin	Add product
PUT	/products/:id	Admin	Update product
DELETE	/products/:id	Admin	Delete product

👤 Sample Users
Admin:
username: admin
password: admin123

User:
username: user
password: user123

🚀 Future Improvements
Pagination & advanced filtering
Unit testing
Deployment (Vercel + Render)
Performance optimization
UI enhancements
👩‍💻 Developer

Muskan Pathan
B.Tech Computer Science & Engineering
Project: Product Management Dashboard
