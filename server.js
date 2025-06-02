const { pipeline } = require('node:stream/promises');
const express = require('express');
const { Pool } = require('pg');
const copyFrom = require('pg-copy-streams').from;
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
    
    // Call the PostgreSQL function AutenticaUsuario
    const functionQuery = 'SELECT * FROM AutenticaUsuario($1, $2)';
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
      INSERT INTO Driver (driverref, number, code, forename, surname, dob, nationality, url)
      VALUES ((SELECT COALESCE($1, $2, $3, $4, $5, $6, $7, NULL)
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
      INSERT INTO Constructors (constructorref, name, nationality, url)
      VALUES ($1, $2, $3, $4)
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
    console.log(`Processing file: ${fileName} in path: ${filePath}`);

    // Check if file is CSV format
    if (!fileName.endsWith('.csv')) {
      fs.unlinkSync(filePath);
      return res.status(400).json({ 
        message: 'Unsupported file format. Please use CSV files with the format: driverref,code,forename,surname,dob,nationality,number,url' 
      });
    }

    // Count lines in file to estimate records processed
    const fileContent = fs.readFileSync(filePath, 'utf8');
    const lineCount = fileContent.split('\n').filter(line => line.trim()).length;
    
    // Get record count before insertion
    const beforeCountResult = await client.query('SELECT COUNT(*) as count FROM Driver');
    const beforeCount = parseInt(beforeCountResult.rows[0].count);

    // Use streaming COPY for efficient bulk insert
    const ingestStream = client.query(copyFrom('COPY Driver(driverref, code, forename, surname, dob, nationality, number, url) FROM STDIN WITH (FORMAT csv, HEADER false)'));
    const sourceStream = fs.createReadStream(filePath);
    await pipeline(sourceStream, ingestStream);

    // Get record count after insertion to calculate actual inserted records
    const afterCountResult = await client.query('SELECT COUNT(*) as count FROM Driver');
    const afterCount = parseInt(afterCountResult.rows[0].count);
    const actualInserted = afterCount - beforeCount;

    client.release();
    fs.unlinkSync(filePath);
    
    res.json({
      message: 'File processed successfully using streaming upload',
      fileName: fileName,
      estimatedRows: lineCount,
      inserted: actualInserted,
      skipped: lineCount - actualInserted,
      uploadMethod: 'PostgreSQL COPY streaming'
    });

  } catch (error) {
    console.error('Error processing file:', error);
    
    // Clean up uploaded file in case of error
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    
    // Provide more specific error messages
    if (error.code === '23505') {
      res.status(409).json({ 
        message: 'File processing failed due to duplicate records. Some drivers may already exist in the database.',
        error: 'Unique constraint violation'
      });
    } else if (error.code === '22P04') {
      res.status(400).json({ 
        message: 'File processing failed due to invalid CSV format. Please check your file format.',
        error: 'Invalid CSV format'
      });
    } else {
      res.status(500).json({ 
        message: 'Failed to process file due to server error.',
        error: error.message 
      });
    }
  }
});

// Reports endpoints
app.get('/api/reports', async (req, res) => {
  if (!req.session.user || !req.session.user.dbConfig) {
    return res.status(401).json({ message: 'Unauthorized: No active session or database configuration missing.' });
  }
  
  const userRole = req.session.user.role;
  let reports = [];
  
  if (userRole === 'admin' || userRole === 'Administrador') {
    reports = [
      {
        id: 'report1',
        name: 'Relatório 1: Status de Resultados',
        description: 'Quantidade de resultados por status',
        requiresParams: false,
        query: `
          SELECT * FROM report1;
        `
      },
      {
        id: 'report2',
        name: 'Relatório 2: Aeroportos Próximos às Cidades',
        description: 'Aeroportos médios e grandes no Brasil próximos às cidades',
        requiresParams: false,
        query: `
          SELECT * FROM report2;
        `
      },
      {
        id: 'report3a',
        name: 'Relatório 3A: Quantidade de Pilotos por Escuderia',
        description: 'Número de pilotos diferentes que correram por cada escuderia',
        requiresParams: false,
        query: `
          SELECT * FROM report3a;
        `
      },
      {
        id: 'report3b',
        name: 'Relatório 3B: Quantidade de Corridas por Escuderia',
        description: 'Número de corridas por escuderia',
        requiresParams: false,
        query: `
          SELECT * FROM report3b;
        `
      },
      {
        id: 'report3c',
        name: 'Relatório 3C: Corridas por Circuito por Escuderia',
        description: 'Estatísticas de voltas por escuderia e circuito',
        requiresParams: false,
        query: `
          SELECT * FROM report3c;
        `
      },
      {
        id: 'report3d',
        name: 'Relatório 3D: Tempo e Voltas por Corrida por Escuderia',
        description: 'Total de tempo e voltas por corrida por escuderia',
        requiresParams: false,
        query: `
          SELECT * FROM report3d;
        `
      }
    ];
  } else if (userRole === 'escuderia' || userRole === 'Escuderia') {
    reports = [
      {
        id: 'report4',
        name: 'Relatório 4: Vitórias por Piloto da Escuderia',
        description: 'Vitórias de cada piloto da sua escuderia',
        requiresParams: false,
        isFunction: true,
        functionName: 'PilotosVitoriasEscuderia'
      },
      {
        id: 'report5',
        name: 'Relatório 5: Status de Resultados da Escuderia',
        description: 'Status dos resultados da sua escuderia',
        requiresParams: false,
        isFunction: true,
        functionName: 'StatusEscuderia'
      }
    ];
  } else if (userRole === 'piloto' || userRole === 'Piloto') {
    reports = [
      {
        id: 'report6',
        name: 'Relatório 6: Pontos por Corrida',
        description: 'Seus pontos por corrida e ano',
        requiresParams: false,
        isFunction: true,
        functionName: 'PontosPiloto'
      },
      {
        id: 'report7',
        name: 'Relatório 7: Status dos Seus Resultados',
        description: 'Status dos seus resultados nas corridas',
        requiresParams: false,
        isFunction: true,
        functionName: 'StatusPiloto'
      }
    ];
  }
  
  res.json({
    userRole: userRole,
    reports: reports
  });
});

app.post('/api/reports/execute', async (req, res) => {
  if (!req.session.user || !req.session.user.dbConfig) {
    return res.status(401).json({ message: 'Unauthorized: No active session or database configuration missing.' });
  }
  
  const { reportId, params } = req.body;
  const userRole = req.session.user.role;
  const pool = new Pool(req.session.user.dbConfig);
  
  try {
    const client = await pool.connect();
    let result;
    
    // Define report queries based on role and reportId
    if (userRole === 'admin' || userRole === 'Administrador') {
      const adminReports = {
        'report1': `
          SELECT
              s.status,
              COALESCE(r.quantidade, 0) AS quantidade
          FROM
              status s
          LEFT JOIN (
              SELECT statusid, COUNT(DISTINCT resultid) AS quantidade
              FROM results
              GROUP BY statusid
          ) r ON s.statusid = r.statusid
          ORDER BY 2 DESC;
        `,
        'report2': `
          SELECT 
              c.name AS cidade,
              a.name AS aeroporto,
              a.city AS cidade_aeroporto,
              earth_distance(
                  ll_to_earth(a.latdeg, a.longdeg),
                  ll_to_earth(c.lat, c.long)
              ) / 1000 AS distancia,
              a.type AS tipo
          FROM airports a
          JOIN geocities15k c
            ON earth_box(ll_to_earth(a.latdeg, a.longdeg), 100000) @> ll_to_earth(c.lat, c.long)
               AND earth_distance(
                   ll_to_earth(a.latdeg, a.longdeg),
                   ll_to_earth(c.lat, c.long)
               ) <= 100000
          WHERE
            a.type IN ('medium_airport', 'large_airport')
            AND a.isocountry = 'BR'
          ORDER BY 2, 4;
        `,
        'report3a': `
          WITH counter AS (
              SELECT 
                  constructorid,
                  COUNT(DISTINCT driverid) as driver_count
              FROM results
              GROUP BY constructorid
          )
          SELECT 
              c.name AS Escuderia,
              COALESCE(co.driver_count, 0) as Pilotos
          FROM constructors c
          LEFT JOIN counter co ON c.constructorid = co.constructorid
          ORDER BY 2 DESC, 1;
        `,
        'report3b': `
          SELECT 
              c.name AS escuderia,
              COALESCE(corridas.corrida, 0) as corridas
          FROM constructors c
          LEFT JOIN (
              SELECT 
                  constructorid,
                  COUNT(DISTINCT raceid) as corrida
              FROM results
              GROUP BY constructorid
          ) corridas ON c.constructorid = corridas.constructorid
          ORDER BY 2 DESC, 1;
        `,
        'report3c': `
          SELECT 
            c.name AS escuderia, 
            c2.name AS circuito, 
            COUNT(DISTINCT r.raceid) AS quantidade_corridas, 
            MIN(r.laps) AS minimo_voltas, 
            MAX(r.laps) AS maximo_voltas, 
            ROUND(AVG(r.laps), 2) AS media_voltas
          FROM constructors c 
          JOIN results r ON r.constructorid = c.constructorid
          JOIN races r2 ON r2.raceid = r.raceid 
          JOIN circuits c2 ON c2.circuitid = r2.circuitid
          GROUP BY 1, 2
          ORDER BY 1, 3 DESC;
        `,
        'report3d': `
          SELECT
            c.name AS escuderia,
            c2.name AS circuito,
            r2.year AS ano,
            SUM(r.laps) AS total_voltas,
            (SUM(r.milliseconds)||' milliseconds')::INTERVAL AS total_tempo
          FROM constructors c
          JOIN results r ON r.constructorid = c.constructorid
          JOIN races r2 ON r2.raceid = r.raceid
          JOIN circuits c2 ON c2.circuitid = r2.circuitid
          WHERE r.milliseconds IS NOT NULL
          GROUP BY 1, 2, 3
          ORDER BY 1, 2, 3;
        `
      };
      
      const query = adminReports[reportId];
      if (!query) {
        return res.status(404).json({ message: 'Report not found.' });
      }
      
      result = await client.query(query);
      
    } else if (userRole === 'escuderia' || userRole === 'Escuderia') {
      const constructorId = req.session.user.idOriginal;
      
      if (reportId === 'report4') {
        result = await client.query('SELECT * FROM PilotosVitoriasEscuderia($1)', [constructorId]);
      } else if (reportId === 'report5') {
        result = await client.query('SELECT * FROM StatusEscuderia($1)', [constructorId]);
      } else {
        return res.status(404).json({ message: 'Report not found.' });
      }
      
    } else if (userRole === 'piloto' || userRole === 'Piloto') {
      const driverId = req.session.user.idOriginal;
      
      if (reportId === 'report6') {
        result = await client.query('SELECT * FROM PontosPiloto($1)', [driverId]);
      } else if (reportId === 'report7') {
        result = await client.query('SELECT * FROM StatusPiloto($1)', [driverId]);
      } else {
        return res.status(404).json({ message: 'Report not found.' });
      }
      
    } else {
      return res.status(403).json({ message: 'Access denied: Invalid user role.' });
    }
    
    client.release();
    
    res.json({
      data: result.rows,
      columns: result.fields.map(field => field.name),
      count: result.rows.length
    });
    
  } catch (error) {
    console.error('Error executing report:', error);
    res.status(500).json({ message: 'Failed to execute report.', error: error.message });
  }
});

app.listen(port, '0.0.0.0', () => {
  console.log(`Server listening on all interfaces at port ${port}`);
  console.log(`Local access: http://localhost:${port}`);
  console.log(`Network access: http://192.168.0.40:${port}`);
});
