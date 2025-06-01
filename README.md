# F1 Dashboard Server

Express.js backend server for F1 Formula 1 dashboard application.

## Features

- PostgreSQL integration with custom functions
- Role-based authentication (Admin, Escuderia, Piloto)
- Session management
- File upload support (CSV/Excel)
- RESTful API endpoints
- SQL injection protection

## API Endpoints

### Authentication
- `POST /login` - User authentication
- `GET /check-auth` - Check authentication status
- `POST /logout` - User logout

### Data Views
- `GET /api/views` - Get role-specific dashboard views
- `GET /api/view/:viewName` - Get individual view with pagination
- `GET /api/user-info` - Get user-specific information

### Admin Operations
- `POST /api/drivers` - Insert new driver
- `POST /api/constructors` - Insert new constructor

### Constructor Operations
- `GET /api/search-drivers` - Search drivers by surname
- `POST /api/upload-drivers` - Upload drivers from file

## Database Functions Used

- `Autentica_Usuario(username, password)` - User authentication
- `ObterInfoUsuario(username)` - Get user information
- `VitoriasEscuderia(constructorId)` - Constructor victories
- `PilotosEscuderia(constructorId)` - Constructor drivers
- `AnosEscuderia(constructorId)` - Constructor years in F1
- `AnosPiloto(driverId)` - Driver years in F1
- `EstatisticasPiloto(driverId)` - Driver statistics

## Installation

```bash
npm install
node server.js
```