const express = require('express');
const routerAluno = require('./aluno.js');
const routerAutor = require('./autor.js');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const dbconn = require('./conexao.js');
const crypto = require('crypto');

const secretWord = 'IFRN2@24';

const app = express();
app.use(bodyParser.json());
app.use('/aluno', verificarToken, routerAluno);
app.use('/autor', verificarToken, routerAutor);

function encriptarSenha(senha) {
  const hash = crypto.createHash('sha256');
  hash.update(senha+secretWord);
  return hash.digest('hex');
}

function gerarToken(payload) {
  return jwt.sign(payload, secretWord, { expiresIn: 120 });
}

function verificarToken(req, res, next) {
  //var token = req.headers['x-access-token'];
  if (req.headers.authorization) {
    var token = req.headers.authorization;
    token = token.replace('Bearer ', '');
    if (!token) {
      return res.status(401).json({
        mensagemErro:
          'Usuário não autenticado. Faça login antes de chamar este recurso.',
      });
    } else {
      jwt.verify(token, secretWord, (error, decoded) => {
        if (error) {
          return res
            .status(403)
            .json({ mensagemErro: 'Token inválido. Faça login novamente.' });
        } else {
          const nomeUsuario = decoded.nomeUsuario;
          console.log(`Usuário ${nomeUsuario} autenticado com sucesso.`);
          next();
        }
      });
    }
  } else {
    return res
      .status(403)
      .json({ mensagemErro: 'Token não detectado. Faça login.' });
  }
}

app.post('/login', (req, res) => {
  const loginName = req.body.loginName;
  const password = encriptarSenha(req.body.password);
  dbconn.query(
    'SELECT nomeusuario, perfil FROM tbusuario WHERE loginname = ? AND password = ?',
    [loginName, password],
    (error, rows) => {
      if (error) {
        console.log('Erro ao processar o comando SQL. ', error.message);
      } else {
        if (rows.length > 0) {
          const payload = { 
            nomeUsuario: rows[0].nomeusuario,
            perfil: rows[0].perfil
          };
          const token = gerarToken(payload);
          res.json({ acessToken: token });
        } else {
          res.status(403).json({ mensagemErro: 'Usuário ou senha inválidos' });
        }
      }
    }
  );

  // if (loginName === 'admin' && password === '123') {
  //   const payload = { nomeUsuario: 'Administrador' };
  //   const token = gerarToken(payload);
  //   res.json({ acessToken: token });
  // } else {
  //   res.status(403).json({ mensagemErro: 'Usuário ou senha inválidos' });
  // }
});

app.post('/cadastrar', (req, res) => {
  const nomeUsuario = req.body.nomeUsuario;
  const loginName = req.body.loginName;
  const password = encriptarSenha(req.body.password);
  const perfil = req.body.perfil;

  const sql = 'INSERT INTO tbusuario( nomeusuario, loginname, password, perfil) VALUES(?,?,?,?)';

  dbconn.query(sql, [nomeUsuario,loginName, password,perfil],
    (error, rows) => {
      if (error) {
        console.log(erro);
        res.status(400).send(erro.message);
      } else {
        res.status(201).send('Usuário cadastrado com sucesso.');
      }
    }
  );
});

app.listen(3000, () => {
  console.log(`Servidor web iniciado na porta 3000`);
});
