# TextMate

TextMate is a full-stack application that provides text transformation services. The frontend is built with React and Vite, and the backend is a Node.js Express server with MongoDB and Redis for data storage and caching.

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Getting Started](#getting-started)
  - [Clone the Repository](#clone-the-repository)
  - [Backend Setup](#backend-setup)
  - [Frontend Setup](#frontend-setup)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)

## Features

**Frontend:**
- User-friendly interface for text transformations.
- Displays transformed text.
- User authentication (signup/login).
- View operation history (for authenticated users).

**Backend:**
- User authentication with JWTs (signup, login).
- Text transformation APIs (uppercase, lowercase, titlecase, reverse, analyze).
- Operation logging to MongoDB.
- Redis caching for operation history.
- Prometheus metrics for monitoring.
- Security measures: Helmet, Express Rate Limit, CORS.

## Prerequisites

Before you begin, ensure you have the following installed on your machine:

- **Node.js**: [Download & Install Node.js](https://nodejs.org/en/download/) (LTS version recommended)
- **npm** (comes with Node.js)
- **MongoDB**: [Download & Install MongoDB Community Server](https://www.mongodb.com/try/download/community)
- **Redis**: [Download & Install Redis](https://redis.io/download/)

## Getting Started

Follow these steps to get your TextMate project up and running.

### Clone the Repository

```bash
git clone https://github.com/mohityadavbkbiet/TextMate.git
cd TextMate
```

### Backend Setup

1.  Navigate to the `Backend` directory:
    ```bash
    cd Backend
    ```

2.  Install backend dependencies:
    ```bash
    npm install
    ```

3.  Create a `.env` file in the `Backend` directory and add the following environment variables. Replace the placeholder values with your actual MongoDB URI, Redis URL, and a strong JWT secret.

    ```
    PORT=5000
    MONGODB_URI=mongodb://localhost:27017/textmate_db
    REDIS_URL=redis://localhost:6379
    JWT_SECRET=your_super_secret_jwt_key_here
    ```
    *Note: For `MONGODB_URI` and `REDIS_URL`, ensure your MongoDB and Redis servers are running.*

4.  Start the backend server:
    ```bash
    node server.js
    ```
    The backend server should now be running on `http://localhost:5000` (or the `PORT` you specified).

### Frontend Setup

1.  Open a new terminal and navigate to the `Frontend` directory:
    ```bash
    cd ../Frontend
    ```

2.  Install frontend dependencies:
    ```bash
    npm install
    ```

3.  Start the frontend development server:
    ```bash
    npm run dev
    ```
    The frontend application should now be running, typically on `http://localhost:5173` (Vite's default port).

## Usage

-   Open your web browser and navigate to the frontend URL (e.g., `http://localhost:5173`).
-   You can now use the text transformation features.
-   Register a new account or log in to access features like operation history.

## Project Structure

```
TextMate/
├── Backend/
│   ├── package.json
│   ├── server.js
│   └── ... (other backend files)
├── Frontend/
│   ├── package.json
│   ├── src/
│   │   ├── App.jsx
│   │   └── ... (other frontend files)
│   └── ... (other frontend files)
├── .gitignore
├── README.md
└── ... (other root level files)
```

## Contributing

Contributions are welcome! Please feel free to open issues or submit pull requests.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
