E-Commerce Website

Description:
-------------
This is a Node.js web application for an e-commerce platform. It includes features such as user registration,
login, order creation, and an admin panel for data management (users, products, orders, and categories).

Prerequisites:
--------------
- Node.js (v14 or later is recommended)
- MongoDB (either via MongoDB Atlas or a local MongoDB server)
- Git (if you plan to clone the repository)

Setup and Launch Instructions:
-------------------------------
1. Clone the Repository:
   If you haven't already, clone the repository using Git:
   
     ```git clone <repository_url>```

3. Navigate to the Project Directory:
4. 
     ```cd <project_directory>```

5. Install Dependencies:
   Run the following command to install all necessary packages:
   
     ```npm install express mongoose ejs bcrypt express-session express-rate-limit dotenv method-override```

6. Configure Environment Variables:
   Create a file named ".env" in the root directory and add the following variables:
   
     ```MONGODB_URI=<your MongoDB connection string>```
   
     ```PORT=3000  (Optional, defaults to 3000 if not set)```

7. Launch the Website Locally:
   
   Start the server using:

   ```node server.js```

10. Access the Website:
   Open your browser and navigate to:
     http://localhost:3000
