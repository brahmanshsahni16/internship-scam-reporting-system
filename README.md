# internship-scam-reporting-system
DBMS project for internship verification and scam reporting

# Internship & Job Scam Reporting System

## 📌 Overview  
This project is a DBMS-based system designed to help students identify genuine internship and job opportunities and avoid scams. It provides a centralized platform where users can view company details, explore internships, and report suspicious or fraudulent activities.

The system stores all data in a structured relational database and uses reported cases to evaluate the risk level of companies, helping users make informed decisions.

---

## 🎯 Objectives  
- To design a relational database for managing users, companies, internships, and scam reports  
- To reduce data redundancy using normalization (up to 3NF)  
- To implement relationships using primary and foreign keys  
- To analyze scam reports using SQL queries and aggregation  
- To ensure data consistency using constraints and transactions  

---

## ⚙️ Features  
- User registration and role management  
- Company and internship listing  
- Scam reporting system  
- Categorization of scam types  
- Company risk evaluation based on reports  
- Structured and normalized database design  

---

## 🗄️ Database Design  
The system includes the following main tables:

- USERS  
- COMPANIES  
- INTERNSHIPS  
- SCAM_REPORTS  
- REPORT_CATEGORIES  
- REPORT_CATEGORY_MAP  

The database is normalized up to Third Normal Form (3NF) to eliminate redundancy and maintain consistency.

---

## 🛠️ Technologies Used  
- MySQL / PostgreSQL  
- SQL  
- PL/SQL  
- Node.js  
- Express.js  
- MySQL Workbench  

---

## 📊 Key Concepts Used  
- Relational Database Design  
- Normalization (1NF, 2NF, 3NF)  
- Primary & Foreign Keys  
- Joins and Aggregate Functions  
- Stored Procedures and Triggers  
- Transaction Management (ACID properties)  

---

## 🚀 How It Works  
- Users can browse companies and internships  
- Users can report scams based on their experience  
- Reports are verified by admin  
- Approved reports are used to calculate company risk level  
- Risk level helps other users avoid fraudulent companies  

---

## 📁 Project Structure  
```
/database       -> SQL schema and queries  
/backend        -> Node.js server code  
/docs           -> Synopsis, diagrams, report  
/frontend       -> (optional UI)
```

---

## 📌 Future Improvements  
- Add authentication system  
- Build a full frontend interface  
- Add real-time alerts for high-risk companies  
- Improve admin dashboard  

---

## 👨‍💻 Authors  
- Brahmansh Singh Sahni 
- Samarth Gulati 
- Team Member 3  

---

## 📄 License  
This project is for academic purposes.
