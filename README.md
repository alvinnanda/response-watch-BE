# ResponseWatch Backend

Go Fiber v3 backend API for ResponseWatch - A modern request tracking and response management system.

## 🚀 Tech Stack

- **Framework**: Go Fiber v3
- **Database**: PostgreSQL (via Supabase)
- **Authentication**: JWT + Session-based
- **Encryption**: AES-256 for sensitive data

## 📋 Features

- User authentication (register, login, profile management)
- Request management with encryption
- Vendor group management
- Public Smart Link system
- Rate limiting
- CORS support

## 🛠️ Local Development

### Prerequisites

- Go 1.21+
- PostgreSQL (or Supabase account)
- Air (for live reload)

### Setup

1. Clone the repository:
```bash
git clone https://github.com/alvinnanda/response-watch-BE.git
cd response-watch-BE
```

2. Copy environment file:
```bash
cp .env.example .env
```

3. Update `.env` with your configuration:
```bash
DATABASE_URL=your_supabase_connection_string
JWT_SECRET=your_jwt_secret
SESSION_SECRET=your_session_secret
APP_SECRET=your_32_byte_encryption_key
```

4. Install dependencies:
```bash
go mod download
```

5. Run migrations (if using golang-migrate):
```bash
migrate -path migrations -database "your_database_url" up
```

6. Run the server:
```bash
# With Air (live reload)
air

# Or directly
go run cmd/server/main.go
```

Server will start on `http://localhost:3000`

## 🌐 API Endpoints

### Public Endpoints

- `GET /api/health` - Health check
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login
- `GET /api/public/t/:token` - Get request by token
- `POST /api/public/t/:token/start` - Start response
- `POST /api/public/t/:token/finish` - Finish response
- `POST /api/public/requests` - Create public request
- `GET /api/public/monitoring/:username` - Get user's public requests

### Protected Endpoints (Requires JWT)

**Auth:**
- `POST /api/auth/logout` - Logout
- `GET /api/auth/me` - Get current user
- `PUT /api/auth/profile` - Update profile

**Requests:**
- `GET /api/requests` - List requests
- `POST /api/requests` - Create request
- `GET /api/requests/:id` - Get request
- `PUT /api/requests/:id` - Update request
- `DELETE /api/requests/:id` - Delete request
- `GET /api/requests/stats` - Get statistics

**Vendor Groups:**
- `GET /api/vendor-groups` - List vendor groups
- `POST /api/vendor-groups` - Create vendor group
- `GET /api/vendor-groups/:id` - Get vendor group
- `PUT /api/vendor-groups/:id` - Update vendor group
- `DELETE /api/vendor-groups/:id` - Delete vendor group

## 📁 Project Structure

```
backend/
├── cmd/
│   └── server/
│       └── main.go          # Application entry point
├── config/
│   └── config.go            # Configuration management
├── internal/
│   ├── database/
│   │   └── database.go      # Database connection
│   ├── handlers/            # HTTP handlers
│   │   ├── auth.go
│   │   ├── request.go
│   │   └── vendor_group.go
│   ├── middleware/          # Middleware
│   │   ├── auth.go
│   │   ├── cors.go
│   │   └── ratelimit.go
│   ├── models/              # Data models
│   │   ├── user.go
│   │   ├── request.go
│   │   └── vendor_group.go
│   ├── routes/
│   │   └── routes.go        # Route definitions
│   └── services/            # Business logic
│       ├── auth.go
│       ├── crypto.go
│       └── jwt.go
├── migrations/              # Database migrations
├── .env.example             # Environment template
├── go.mod
└── go.sum
```

## 🔒 Security

- JWT tokens for authentication
- Session-based authentication
- AES-256 encryption for sensitive data
- Rate limiting on public endpoints
- CORS protection
- Password hashing with bcrypt

## 📝 Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `PORT` | Server port | `3000` |
| `ENV` | Environment | `development` or `production` |
| `DATABASE_URL` | PostgreSQL connection string | `postgres://...` |
| `JWT_SECRET` | JWT signing secret | Random 32+ chars |
| `SESSION_SECRET` | Session signing secret | Random 32+ chars |
| `APP_SECRET` | AES encryption key (32 bytes) | Random 32 chars |
| `ALLOWED_ORIGINS` | CORS allowed origins | `http://localhost:5173` |
| `SESSION_EXPIRY_HOURS` | Session expiry in hours | `168` (7 days) |

## 🧪 Testing

```bash
go test ./...
```

## 📄 License

MIT

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📧 Contact

For questions or support, please open an issue on GitHub.
