Node.js Authentication Backend


This is a Node.js backend application providing user authentication with email/password and OAuth integration for Google, Facebook, X.com (formerly Twitter), and LinkedIn. The app uses Express.js for routing, Passport.js for authentication strategies, and MongoDB for database storage.

Features
User authentication via email and password.
OAuth authentication with:
Google
Facebook
X.com (formerly Twitter)
LinkedIn
JWT-based authentication for securing API routes.
User session management.
Password hashing with bcrypt.
API documentation using Swagger (optional).
Technologies Used
Node.js
Express.js
Passport.js
MongoDB (with Mongoose)
JSON Web Token (JWT)
bcrypt (for password hashing)
OAuth 2.0 and OAuth 1.0 (for social logins)
dotenv (for environment variable management)
Getting Started
Prerequisites
Node.js (v14.x or later)
MongoDB (local or cloud database)
OAuth client IDs and secrets from:
Google Cloud
Facebook Developer Console
X.com (Twitter Developer Console)
LinkedIn Developer Console
Installation
Clone the repository:

bash
Copy code
git clone https://github.com/Adityaverma4648/nodejs-auth.git
cd auth-backend
Install dependencies:

bash
Copy code
npm install
Set up environment variables:

Create a .env file in the root directory and add the following variables:

bash
Copy code
PORT=3000
MONGO_URI=your_mongodb_connection_string
JWT_SECRET=your_jwt_secret_key
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
FACEBOOK_CLIENT_ID=your_facebook_client_id
FACEBOOK_CLIENT_SECRET=your_facebook_client_secret
TWITTER_CONSUMER_KEY=your_xcom_consumer_key
TWITTER_CONSUMER_SECRET=your_xcom_consumer_secret
LINKEDIN_CLIENT_ID=your_linkedin_client_id
LINKEDIN_CLIENT_SECRET=your_linkedin_client_secret
Run the app:

bash
Copy code
npm start
Access the API:

The server will run at http://localhost:3000.
Use Postman or any API client to test the authentication routes.
API Endpoints
Auth Routes
Method	Endpoint	Description
POST	/auth/register	Register a new user
POST	/auth/login	Login with email and password
GET	/auth/google	OAuth login with Google
GET	/auth/facebook	OAuth login with Facebook
GET	/auth/xcom	OAuth login with X.com
GET	/auth/linkedin	OAuth login with LinkedIn
GET	/auth/logout	Logout the user
Protected Routes
Method	Endpoint	Description
GET	/user/profile	Get authenticated user profile
PUT	/user/update	Update user profile
Example .env file
bash
Copy code
PORT=3000
MONGO_URI=mongodb://localhost:27017/auth-db
JWT_SECRET=mysecretkey123
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
FACEBOOK_CLIENT_ID=your-facebook-client-id
FACEBOOK_CLIENT_SECRET=your-facebook-client-secret
TWITTER_CONSUMER_KEY=your-xcom-consumer-key
TWITTER_CONSUMER_SECRET=your-xcom-consumer-secret
LINKEDIN_CLIENT_ID=your-linkedin-client-id
LINKEDIN_CLIENT_SECRET=your-linkedin-client-secret
Usage
Register: Create a new user by posting email, password, and other relevant data to /auth/register.
Login: Authenticate a user using /auth/login by sending email and password.
OAuth Login: Redirect users to the corresponding OAuth login URL, such as /auth/google, /auth/facebook, /auth/xcom, or /auth/linkedin.
Future Improvements
Add refresh tokens for enhanced security.
Integrate email verification and password reset features.
Implement rate-limiting and brute-force protection.
Add more OAuth providers as needed.
Contributing
Feel free to open issues, submit pull requests, or suggest new features to improve the application.

License
This project is licensed under the MIT License.
