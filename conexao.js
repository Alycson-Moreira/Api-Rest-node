const mysql = require('mysql');

const dbconn = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'dbbiblioteca'
});

dbconn.connect((err) => {
    if (err) {
        console.log(err);
    } else {
        console.log('Conectado com sucesso ao banco de dados');
    }
});

module.exports = dbconn;