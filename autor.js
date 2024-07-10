const express = require('express');
const routerAutor = express.Router();
const dbconn = require('./conexao.js');

routerAutor.get('/', (req, res) => {
    const sql = 'SELECT * FROM tbautor';
    dbconn.query(sql, (erro, linhas) => {
        if (erro) {
            console.log(erro);
        } else {
            res.json(linhas);
        }
    });
});

routerAutor.get('/:id', (req, res) => {
    const id = req.params.id;
    const sql = 'SELECT * FROM tbautor WHERE IdAutor = ?';
    dbconn.query(sql, [id], (erro, linhas) => {
        if (erro) {
            console.log(erro);
        } else {
            if (linhas.length > 0){
                res.json(linhas[0]);
            } else {
                res.status(404).send('Registro não localizado');
            }
        }
    });
});

module.exports = routerAutor;