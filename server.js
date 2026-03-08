const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json()); // Permite receber dados no formato JSON

const SECRET_KEY = "minha_chave_super_secreta_do_portfolio";

// Conecta ao banco SQLite (cria o arquivo auth_data.db)
const db = new sqlite3.Database('./auth_data.db');

// Cria a tabela de usuários
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT, 
    email TEXT UNIQUE, 
    senha TEXT
  )`);
});

// 🟢 ROTA 1: CADASTRAR USUÁRIO (Criptografando a senha)
app.post('/api/registrar', async (req, res) => {
  const { email, senha } = req.body;

  try {
    // Embaralha a senha 10 vezes (Salt)
    const senhaCriptografada = await bcrypt.hash(senha, 10);

    db.run("INSERT INTO usuarios (email, senha) VALUES (?, ?)", [email, senhaCriptografada], function(err) {
      if (err) return res.status(400).json({ erro: "E-mail já cadastrado!" });
      res.status(201).json({ mensagem: "Usuário criado com sucesso!" });
    });
  } catch (error) {
    res.status(500).json({ erro: "Erro ao processar segurança." });
  }
});

// 🔵 ROTA 2: FAZER LOGIN (Gerando o Token JWT)
app.post('/api/login', (req, res) => {
  const { email, senha } = req.body;

  db.get("SELECT * FROM usuarios WHERE email = ?", [email], async (err, usuario) => {
    if (err) return res.status(500).json({ erro: "Erro no servidor." });
    if (!usuario) return res.status(401).json({ erro: "Usuário não encontrado." });

    // Compara a senha digitada com a senha criptografada do banco
    const senhaValida = await bcrypt.compare(senha, usuario.senha);
    if (!senhaValida) return res.status(401).json({ erro: "Senha incorreta." });

    // Se deu certo, cria o Token de acesso
    const token = jwt.sign({ id: usuario.id, email: usuario.email }, SECRET_KEY, { expiresIn: '1h' });
    
    res.json({ mensagem: "Login efetuado com sucesso!", token: token });
  });
});

// Liga o servidor
app.listen(3000, () => {
  console.log('🔒 API de Segurança rodando na porta 3000!');
});