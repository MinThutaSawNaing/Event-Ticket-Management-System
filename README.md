# 🎟️ Event Ticket Management System (ETMS)

A full-stack **Event Ticket Management System** built with **Python (Flask)** and **MongoDB**.  
The application allows users to browse events, purchase tickets, and view their purchases, while organizers and admins can manage events, ticket types, and view sales analytics.

---

## ✨ Features

### 🔐 Authentication & Roles
- Session-based authentication using **Flask-Login**
- Role-based access control:
  - **Admin**
  - **Organizer**
  - **Attendee**
- Secure password hashing
- Default admin user auto-created on first run

### 📅 Event Management
- Create, update, and delete events
- Category-based event organization
- Date, venue, and category filtering
- Organizer-only event management
- Admin override permissions

### 🎫 Ticketing
- Multiple ticket types per event
- Price and quantity control
- Oversell-safe ticket purchasing using atomic MongoDB updates
- Real-time ticket availability tracking

### 💳 Purchases
- Purchase tickets securely
- View purchase history (“My Tickets”)
- Automatic total price calculation

### 📊 Sales Dashboard
- Total revenue summary
- Tickets sold per event
- Most popular events
- Organizer-specific sales views

---

## 🧰 Tech Stack

### Backend
- **Python 3**
- **Flask**
- **Flask-Login**
- **PyMongo**
- **MongoDB**

### Frontend
- HTML5
- CSS3
- Vanilla JavaScript

---

## 📂 Project Structure

```text
/
├── app.py          # Flask backend (single file)
├── main.html       # Frontend UI (served at "/")
├── README.md       # Documentation
├── requirements.txt # Requirements to run the backend server
