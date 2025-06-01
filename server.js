const express = require('express');
const { Pool } = require('pg');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const csv = require('csv-parser');
const fs = require('fs');
const ExcelJS = require('exceljs');

const app = express();
const port = process.env.PORT || 3001;

// Configure multer for file uploads
const upload = multer({ dest: 'uploads/' });

app.use(express.json());

app.use(session({
  secret: 'fd3985dfjDio@88',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));

const dbConfig = {
  user: 'postgres',
  host: 'localhost',
  database: 'f1db',
  password: 'postgres',
  port: 5432,
};

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required.' });
  }

  const pool = new Pool(dbConfig);

  try {
    const client = await pool.connect();
    
    // Call the PostgreSQL function Autentica_Usuario
    const functionQuery = 'SELECT * FROM Autentica_Usuario($1, $2)';
    const result = await client.query(functionQuery, [username, password]);
    
    client.release();

    if (result.rows.length === 0) {
      return res.status(500).json({ message: 'Unexpected error: No result from authentication function.' });
    }

    const authResult = result.rows[0];
    
    if (!authResult.success) {
      return res.status(401).json({ message: authResult.message });
    }

    // Store user information in session
    req.session.user = {
      userId: authResult.userid,
      username: authResult.login,
      role: authResult.tipo,
      idOriginal: authResult.idoriginal,
      dbConfig: dbConfig
    };
    
    console.log(`Login successful. User ${authResult.login} with role ${authResult.tipo} authenticated. Audit record created.`);
    res.json({
      message: authResult.message,
      user: {
        userId: authResult.userid,
        username: authResult.login,
        role: authResult.tipo,
        idOriginal: authResult.idoriginal
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    if (req.session) {
      req.session.destroy(err => {
        if (err) {
          console.error("Error destroying session during login failure:", err);
        }
      });
    }
    res.status(500).json({ message: 'Login failed due to a server error.' });
  }
});

app.get('/check-auth', (req, res) => {
  if (req.session.user) {
    res.json({ isAuthenticated: true, user: req.session.user });
  } else {
    res.json({ isAuthenticated: false });
  }
});

app.post('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).json({ message: 'Could not log out, please try again.'});
    }
    res.clearCookie('connect.sid');
    res.json({ message: 'Logout successful' });
  });
});

app.get('/api/views', async (req, res) => {
  console.log('Session data:', req.session);
  if (!req.session.user || !req.session.user.dbConfig) {
    return res.status(401).json({ message: 'Unauthorized: No active session or database configuration missing.' });
  }
  const userRole = req.session.user.role;
  console.log('User role from session:', userRole, 'Type:', typeof userRole);
  const pool = new Pool(req.session.user.dbConfig);

  try {
    const client = await pool.connect();
    let views = [];
    
    // Determine which views to fetch based on user role
    if (userRole === 'admin' || userRole === 'Administrador') {
      const viewQueries = [
        { name: 'Resumo Geral', query: 'SELECT * FROM adm_view1' },
        { name: 'Corridas', query: 'SELECT * FROM adm_view2' },
        { name: 'Pontuação Geral - Escuderias', query: 'SELECT * FROM adm_view3' },
        { name: 'Pontuação Geral - Pilotos', query: 'SELECT * FROM adm_view4' }
      ];
      
      for (const view of viewQueries) {
        try {
          const result = await client.query(view.query);
          views.push({
            name: view.name,
            data: result.rows,
            columns: result.fields.map(field => field.name)
          });
        } catch (error) {
          console.error(`Error fetching ${view.name}:`, error);
          views.push({
            name: view.name,
            data: [],
            columns: [],
            error: `Failed to fetch ${view.name}`
          });
        }
      }
    } else if (userRole === 'escuderia' || userRole === 'Escuderia') {
      const viewQueries = [
        { name: 'Vitórias na temporada', query: 'SELECT * FROM VitoriasEscuderia($1)' },
        { name: 'Total de pilotos', query: 'SELECT * FROM PilotosEscuderia($1)' },
        { name: 'Anos na Fórmula 1', query: 'SELECT * FROM AnosEscuderia($1)' }
      ];

      const constructorId = req.session.user.idOriginal;
      
      for (const view of viewQueries) {
        try {
          const result = await client.query(view.query, [constructorId]);
          views.push({
            name: view.name,
            data: result.rows,
            columns: result.fields.map(field => field.name)
          });
        } catch (error) {
          console.error(`Error fetching ${view.name}:`, error);
          views.push({
            name: view.name,
            data: [],
            columns: [],
            error: `Failed to fetch ${view.name}`
          });
        }
      }
    } else if (userRole === 'piloto' || userRole === 'Piloto') {
      const viewQueries = [
        { name: 'Anos na Fórmula 1', query: 'SELECT * FROM AnosPiloto($1)' },
        { name: 'Estatísticas gerais', query: 'SELECT * FROM EstatisticasPiloto($1)' }
      ];

      const driverId = req.session.user.idOriginal;
      
      for (const view of viewQueries) {
        try {
          const result = await client.query(view.query, [driverId]);
          views.push({
            name: view.name,
            data: result.rows,
            columns: result.fields.map(field => field.name)
          });
        } catch (error) {
          console.error(`Error fetching ${view.name}:`, error);
          views.push({
            name: view.name,
            data: [],
            columns: [],
            error: `Failed to fetch ${view.name}`
          });
        }
      }
    } else {
      client.release();
      return res.status(403).json({ message: 'Access denied: Invalid user role.' });
    }

    client.release();
    res.json({
      userRole: userRole,
      views: views
    });

  } catch (error) {
    console.error('Error fetching views:', error);
    res.status(500).json({ message: 'Failed to fetch dashboard views.' });
  }
});

app.get('/api/drivers', async (req, res) => {
  if (!req.session.user || !req.session.user.dbConfig) {
    return res.status(401).json({ message: 'Unauthorized: No active session or database configuration missing.' });
  }

  const pool = new Pool(req.session.user.dbConfig); 

  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 20;
  const offset = (page - 1) * limit;

  try {
    const client = await pool.connect();
    const totalResult = await client.query('SELECT COUNT(*) FROM Driver;');
    const totalDrivers = parseInt(totalResult.rows[0].count);
    
    const queryText = `
      SELECT *
      FROM Driver 
      ORDER BY COUNT(*) OVER (PARTITION BY nationality) DESC, nationality, forename, surname 
      LIMIT $1 OFFSET $2;
    `;
    const result = await client.query(queryText, [limit, offset]);
    client.release();
    
    res.json({
      drivers: result.rows,
      totalPages: Math.ceil(totalDrivers / limit),
      currentPage: page,
      totalDrivers: totalDrivers
    });
  } catch (error) {
    console.error('Error fetching drivers:', error);
    res.status(500).json({ message: 'Failed to fetch drivers.' });
  }
});

// New endpoint for individual view with pagination
app.get('/api/view/:viewName', async (req, res) => {
  console.log('Session data:', req.session);
  if (!req.session.user || !req.session.user.dbConfig) {
    return res.status(401).json({ message: 'Unauthorized: No active session or database configuration missing.' });
  }
  
  const userRole = req.session.user.role;
  const { viewName } = req.params;
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 20;
  const offset = (page - 1) * limit;
  
  console.log(`Fetching ${viewName} for role ${userRole}, page ${page}, limit ${limit}`);
  
  // Map view names to their corresponding queries and user access
  const viewConfigurations = {
    // Admin views
    'Resumo Geral': {
      roles: ['admin', 'Administrador'],
      query: 'SELECT * FROM adm_view1',
      countQuery: 'SELECT COUNT(*) as total FROM adm_view1'
    },
    'Corridas': {
      roles: ['admin', 'Administrador'],
      query: 'SELECT * FROM adm_view2',
      countQuery: 'SELECT COUNT(*) as total FROM adm_view2'
    },
    'Pontuação Geral - Escuderias': {
      roles: ['admin', 'Administrador'],
      query: 'SELECT * FROM adm_view3',
      countQuery: 'SELECT COUNT(*) as total FROM adm_view3'
    },
    'Pontuação Geral - Pilotos': {
      roles: ['admin', 'Administrador'],
      query: 'SELECT * FROM adm_view4',
      countQuery: 'SELECT COUNT(*) as total FROM adm_view4'
    },
    // Escuderia views
    'Vitórias na temporada': {
      roles: ['escuderia', 'Escuderia'],
      query: 'SELECT * FROM VitoriasEscuderia($1)',
      countQuery: 'SELECT COUNT(*) as total FROM VitoriasEscuderia($1)',
      requiresUserId: true
    },
    'Total de pilotos': {
      roles: ['escuderia', 'Escuderia'],
      query: 'SELECT * FROM PilotosEscuderia($1)',
      countQuery: 'SELECT COUNT(*) as total FROM PilotosEscuderia($1)',
      requiresUserId: true
    },
    'Anos na Fórmula 1': {
      roles: ['escuderia', 'Escuderia', 'piloto', 'Piloto'],
      query: (role) => {
        if (role === 'escuderia' || role === 'Escuderia') {
          return 'SELECT * FROM AnosEscuderia($1)';
        } else {
          return 'SELECT * FROM AnosPiloto($1)';
        }
      },
      countQuery: (role) => {
        if (role === 'escuderia' || role === 'Escuderia') {
          return 'SELECT COUNT(*) as total FROM AnosEscuderia($1)';
        } else {
          return 'SELECT COUNT(*) as total FROM AnosPiloto($1)';
        }
      },
      requiresUserId: true
    },
    // Piloto views
    'Estatísticas gerais': {
      roles: ['piloto', 'Piloto'],
      query: 'SELECT * FROM EstatisticasPiloto($1)',
      countQuery: 'SELECT COUNT(*) as total FROM EstatisticasPiloto($1)',
      requiresUserId: true
    }
  };
  
  const viewConfig = viewConfigurations[viewName];
  
  if (!viewConfig) {
    return res.status(404).json({ message: 'View not found.' });
  }
  
  if (!viewConfig.roles.includes(userRole)) {
    return res.status(403).json({ message: 'Access denied: You do not have permission to access this view.' });
  }
  
  const pool = new Pool(req.session.user.dbConfig);

  try {
    const client = await pool.connect();
    
    let dataQuery, countQuery;
    const queryParams = [];
    
    if (viewConfig.requiresUserId) {
      const userId = req.session.user.idOriginal;
      queryParams.push(userId);
      
      if (typeof viewConfig.query === 'function') {
        dataQuery = viewConfig.query(userRole);
        countQuery = viewConfig.countQuery(userRole);
      } else {
        dataQuery = viewConfig.query;
        countQuery = viewConfig.countQuery;
      }
    } else {
      dataQuery = viewConfig.query;
      countQuery = viewConfig.countQuery;
    }
    
    // Get total count first
    const countResult = await client.query(countQuery, queryParams);
    const totalCount = parseInt(countResult.rows[0].total);
    
    // Get paginated data
    const paginatedQuery = `${dataQuery} LIMIT $${queryParams.length + 1} OFFSET $${queryParams.length + 2}`;
    const dataResult = await client.query(paginatedQuery, [...queryParams, limit, offset]);
    
    client.release();
    
    const totalPages = Math.ceil(totalCount / limit);
    
    res.json({
      userRole: userRole,
      view: {
        name: viewName,
        data: dataResult.rows,
        columns: dataResult.fields.map(field => field.name),
        totalCount,
        currentPage: page,
        totalPages,
        hasNextPage: page < totalPages,
        hasPreviousPage: page > 1
      }
    });

  } catch (error) {
    console.error(`Error fetching ${viewName}:`, error);
    res.status(500).json({ 
      message: `Failed to fetch ${viewName}.`,
      view: {
        name: viewName,
        data: [],
        columns: [],
        error: `Failed to fetch ${viewName}: ${error.message}`
      }
    });
  }
});

// Get user information endpoint
app.get('/api/user-info', async (req, res) => {
  if (!req.session.user || !req.session.user.dbConfig) {
    return res.status(401).json({ message: 'Unauthorized: No active session or database configuration missing.' });
  }

  const username = req.session.user.username;
  const pool = new Pool(req.session.user.dbConfig);

  try {
    const client = await pool.connect();
    
    // Call the PostgreSQL function ObterInfoUsuario
    const functionQuery = 'SELECT * FROM ObterInfoUsuario($1)';
    const result = await client.query(functionQuery, [username]);
    
    client.release();

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'User information not found.' });
    }

    const userInfo = result.rows[0];
    
    res.json({
      userInfo: {
        login: userInfo.login,
        tipo: userInfo.tipo,
        nomePiloto: userInfo.nomepiloto,
        pilotoEscuderiaAtual: userInfo.pilotoescuderiaatual,
        nomeEscuderia: userInfo.nomeescuderia,
        quantidadePilotos: userInfo.quantidadepilotos
      }
    });

  } catch (error) {
    console.error('Error fetching user information:', error);
    res.status(500).json({ message: 'Failed to fetch user information.' });
  }
});

// Insert new driver endpoint
app.post('/api/drivers', async (req, res) => {
  if (!req.session.user || !req.session.user.dbConfig) {
    return res.status(401).json({ message: 'Unauthorized: No active session or database configuration missing.' });
  }

  const userRole = req.session.user.role;
  if (userRole !== 'admin' && userRole !== 'Administrador') {
    return res.status(403).json({ message: 'Access denied: Only administrators can insert drivers.' });
  }

  const { driverRef, number, code, forename, surname, dob, nationality } = req.body;

  if (!driverRef || !number || !code || !forename || !surname || !dob || !nationality) {
    return res.status(400).json({ message: 'All fields are required.' });
  }

  const pool = new Pool(req.session.user.dbConfig);

  try {
    const client = await pool.connect();
    
    const insertQuery = `
      INSERT INTO Driver (driverid, driverref, number, code, forename, surname, dob, nationality, url)
      VALUES ((SELECT COALESCE(MAX(driverid), 0) + 1 FROM driver), $1, $2, $3, $4, $5, $6, $7, NULL)
    `;
    
    const result = await client.query(insertQuery, [driverRef, parseInt(number), code, forename, surname, dob, nationality]);
    
    client.release();
    
    res.json({
      message: 'Driver inserted successfully',
      driver: result.rows[0]
    });

  } catch (error) {
    console.error('Error inserting driver:', error);
    if (error.code === '23505') { // Unique violation
      res.status(400).json({ message: 'Driver with this reference, or full name (forename + surname) already exists.' });
    } else {
      res.status(500).json({ message: 'Failed to insert driver.' });
    }
  }
});

// Insert new constructor endpoint
app.post('/api/constructors', async (req, res) => {
  if (!req.session.user || !req.session.user.dbConfig) {
    return res.status(401).json({ message: 'Unauthorized: No active session or database configuration missing.' });
  }

  const userRole = req.session.user.role;
  if (userRole !== 'admin' && userRole !== 'Administrador') {
    return res.status(403).json({ message: 'Access denied: Only administrators can insert constructors.' });
  }

  const { constructorRef, name, nationality, url } = req.body;

  if (!constructorRef || !name || !nationality || !url) {
    return res.status(400).json({ message: 'All fields are required.' });
  }

  const pool = new Pool(req.session.user.dbConfig);

  try {
    const client = await pool.connect();
    
    const insertQuery = `
      INSERT INTO Constructors (constructorid, constructorref, name, nationality, url)
      VALUES ((SELECT COALESCE(MAX(constructorid), 0) + 1 FROM constructors), $1, $2, $3, $4)
    `;
    
    const result = await client.query(insertQuery, [constructorRef, name, nationality, url]);
    
    client.release();
    
    res.json({
      message: 'Constructor inserted successfully',
      constructor: result.rows[0]
    });

  } catch (error) {
    console.error('Error inserting constructor:', error);
    if (error.code === '23505') { // Unique violation
      res.status(400).json({ message: 'Constructor with this reference already exists.' });
    } else {
      res.status(500).json({ message: 'Failed to insert constructor.' });
    }
  }
});

// Search drivers by surname endpoint
app.get('/api/search-drivers', async (req, res) => {
  if (!req.session.user || !req.session.user.dbConfig) {
    return res.status(401).json({ message: 'Unauthorized: No active session or database configuration missing.' });
  }

  const userRole = req.session.user.role;
  if (userRole !== 'escuderia' && userRole !== 'Escuderia') {
    return res.status(403).json({ message: 'Access denied: Only constructor users can search drivers.' });
  }

  const { surname } = req.query;

  if (!surname) {
    return res.status(400).json({ message: 'Surname parameter is required.' });
  }

  // Extract constructorref from user's login by removing '_c' suffix
  const userLogin = req.session.user.username;
  const constructorId = req.session.user.idOriginal;
  const constructorRef = userLogin.endsWith('_c') ? userLogin.slice(0, -2) : userLogin;
  
  console.log(`Searching drivers for constructor: ${constructorRef}, surname: ${surname}`);

  const pool = new Pool(req.session.user.dbConfig);

  try {
    const client = await pool.connect();
    
    const searchQuery = `
      SELECT 
        d.forename || ' ' || d.surname AS "Nome", 
        d.dob AS "Data de Nascimento", 
        d.nationality AS "Nacionalidade"
      FROM driver d
      JOIN results r ON r.driverid = d.driverid
      JOIN constructors c ON c.constructorid = r.constructorid
      WHERE c.constructorid = $1 
        AND LOWER(d.surname) LIKE LOWER($2)
      GROUP BY d.driverid, d.forename, d.surname, d.dob, d.nationality, c.name
      ORDER BY d.surname, d.forename;
    `;
    
    const result = await client.query(searchQuery, [constructorId, `%${surname}%`]);
    
    client.release();
    
    res.json({
      drivers: result.rows,
      count: result.rows.length,
      searchCriteria: {
        constructorId: constructorId,
        surname: surname
      }
    });

  } catch (error) {
    console.error('Error searching drivers:', error);
    res.status(500).json({ message: 'Failed to search drivers.' });
  }
});

// Upload drivers file endpoint
app.post('/api/upload-drivers', upload.single('file'), async (req, res) => {
  if (!req.session.user || !req.session.user.dbConfig) {
    return res.status(401).json({ message: 'Unauthorized: No active session or database configuration missing.' });
  }

  const userRole = req.session.user.role;
  if (userRole !== 'escuderia' && userRole !== 'Escuderia') {
    return res.status(403).json({ message: 'Access denied: Only constructor users can upload driver files.' });
  }

  if (!req.file) {
    return res.status(400).json({ message: 'No file uploaded.' });
  }

  const pool = new Pool(req.session.user.dbConfig);
  let insertedCount = 0;
  let errors = [];

  try {
    const client = await pool.connect();
    const filePath = req.file.path;
    const fileName = req.file.originalname.toLowerCase();
    
    let drivers = [];

    // Parse file based on extension
    if (fileName.endsWith('.csv')) {
      // Parse CSV file
      drivers = await new Promise((resolve, reject) => {
        const results = [];
        fs.createReadStream(filePath)
          .pipe(csv())
          .on('data', (data) => results.push(data))
          .on('end', () => resolve(results))
          .on('error', reject);
      });
    } else if (fileName.endsWith('.xlsx') || fileName.endsWith('.xls')) {
      // Parse Excel file
      const workbook = new ExcelJS.Workbook();
      await workbook.xlsx.readFile(filePath);
      const worksheet = workbook.getWorksheet(1);
      const headers = [];
      
      // Get headers from first row
      worksheet.getRow(1).eachCell((cell, colNumber) => {
        headers[colNumber] = cell.value;
      });
      
      // Get data rows
      worksheet.eachRow((row, rowNumber) => {
        if (rowNumber > 1) { // Skip header row
          const driver = {};
          row.eachCell((cell, colNumber) => {
            if (headers[colNumber]) {
              driver[headers[colNumber]] = cell.value;
            }
          });
          drivers.push(driver);
        }
      });
    } else {
      return res.status(400).json({ message: 'Unsupported file format. Please use CSV or Excel files.' });
    }

    // Insert drivers into database
    for (const driver of drivers) {
      try {
        // Map common field names (case insensitive)
        const driverRef = driver.driverref || driver.driverRef || driver.driver_ref || driver['Driver Ref'];
        const number = driver.number || driver.Number || driver.num;
        const code = driver.code || driver.Code || driver.driver_code;
        const forename = driver.forename || driver.Forename || driver.firstname || driver['First Name'];
        const surname = driver.surname || driver.Surname || driver.lastname || driver['Last Name'];
        const dob = driver.dob || driver.DOB || driver.dateofbirth || driver['Date of Birth'];
        const nationality = driver.nationality || driver.Nationality || driver.country;

        if (!driverRef || !number || !code || !forename || !surname || !dob || !nationality) {
          errors.push(`Row skipped: Missing required fields for driver ${forename} ${surname}`);
          continue;
        }

        const insertQuery = `
          INSERT INTO Driver (driverref, number, code, forename, surname, dob, nationality)
          VALUES ($1, $2, $3, $4, $5, $6, $7)
        `;
        
        await client.query(insertQuery, [driverRef, parseInt(number), code, forename, surname, dob, nationality]);
        insertedCount++;
        
      } catch (error) {
        if (error.code === '23505') { // Unique violation
          errors.push(`Driver ${driver.forename} ${driver.surname} already exists`);
        } else {
          errors.push(`Error inserting driver ${driver.forename} ${driver.surname}: ${error.message}`);
        }
      }
    }
    
    client.release();
    
    // Clean up uploaded file
    fs.unlinkSync(filePath);
    
    res.json({
      message: 'File processed successfully',
      inserted: insertedCount,
      errors: errors,
      totalRows: drivers.length
    });

  } catch (error) {
    console.error('Error processing file:', error);
    
    // Clean up uploaded file in case of error
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    
    res.status(500).json({ message: 'Failed to process file.' });
  }
});

app.listen(port, '0.0.0.0', () => {
  console.log(`Server listening on all interfaces at port ${port}`);
  console.log(`Local access: http://localhost:${port}`);
  console.log(`Network access: http://192.168.0.40:${port}`);
});
