const { Pool } = require('pg');

const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'user_auth',
    password: 'Fourat123*',
    port: 5432,
});

pool.connect((err, client, release) => {
    if (err) {
        console.error('Error connecting to the database:', err.stack);
    } else {
        console.log(`Connected to the PostgreSQL database: ${pool.options.database}`);
    }
    release();
});

module.exports = pool;