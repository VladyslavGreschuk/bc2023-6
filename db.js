const mysql = require('mysql2');

const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    database: 'weblab6'
});

connection.connect(function(err) {
    if (err) {
        console.error('Помилка підключення до MySQL:', err);
        throw err;
    }
    console.log('Підключено до MySQL');
});

module.exports = connection;