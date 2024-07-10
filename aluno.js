const express = require('express');
const routerAluno = express.Router();
const dbconn = require('./conexao.js');

routerAluno.get('/', (req, res) => {
    const sql = 'SELECT * FROM tbaluno';
    dbconn.query(sql, (erro, linhas) => {
        if (erro) {
            console.log(erro);
        } else {
            res.json(linhas);
        }
    });
});

routerAluno.get('/:id', (req, res) => {
    const id = req.params.id;
    const sql = 'SELECT * FROM tbaluno WHERE NuMatricula = ?';
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

routerAluno.post('/', (req, res) => {
    const NuMatricula = req.body.NuMatricula;
    const NoAluno = req.body.NoAluno;
    const TxIngresso = req.body.TxIngresso;
    const IdCurso = req.body.IdCurso;

    const sql = `INSERT INTO tbaluno(NuMatricula, NoAluno, TxIngresso, IdCurso)
        VALUES (?, ?, ?, ?)`;
    dbconn.query(sql, [NuMatricula, NoAluno, TxIngresso, IdCurso], (erro, linhas) => {
        if (erro) {
            console.log(erro);
            res.status(400).send(erro.message);
        } else {
            res.status(201).send('Aluno cadastrado com sucesso.');
        }
    });
});

routerAluno.put('/:id', (req, res) => {
    const id = req.params.id;
    const NoAluno = req.body.NoAluno;
    const TxIngresso = req.body.TxIngresso;
    const IdCurso = req.body.IdCurso;

    const sql = `UPDATE tbaluno SET NoAluno = ?, TxIngresso = ?, IdCurso = ?
        WHERE NuMatricula = ?`;
    dbconn.query(sql, [NoAluno, TxIngresso, IdCurso, id], (erro, linhas) => {
        if (erro) {
            console.log(erro);
            res.status(400).send(erro.message);
        } else {
            if (linhas.affectedRows > 0) {
                res.status(200).send('Aluno atualizado com sucesso.');
            } else {
                res.status(404).send('Registro não localizado');
            }
        }
    });
});

routerAluno.delete('/:id', (req, res) => {
    const id = req.params.id;
    const sql = 'DELETE FROM tbaluno WHERE NuMatricula = ?';
    dbconn.query(sql, [id], (erro, linhas) => {
        if (erro) {
            console.log(erro);
            res.status(400).send(erro.message);
        } else {
            if (linhas.affectedRows > 0) {
                res.status(200).send('Registro excluído com sucesso.');
            } else {
                res.status(404).send('Registro não localizado');
            }
        }
    });
});

module.exports = routerAluno;