const express = require('express')
const mysql = require('mysql2/promise')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
require('dotenv').config()

const app = express()
const PORT = process.env.PORT

app.use(express.json())

const JWT_SECRET = process.env.JWT_SECRET

let db

async function iniciar() {
    db = await mysql.createConnection({
        host: process.env.DB_HOST,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME
    })

    console.log('Conectado ao banco!')

    app.listen(PORT, () => {
        console.log(`Servidor rodando em http://localhost:${PORT}`)
    })
}

function autenticar(req, res, next) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if (!token) {
        return res.status(401).json({ erro: 'Token não enviado' })
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET)
        req.usuario = decoded
        next()
    } catch (erro) {
        return res.status(401).json({ erro: 'Token inválido' })
    }
}

// Suas rotas vão aqui
app.post('/cadastro', async (req, res, next) => {
    try {
        const { nome, email, senha } = req.body

        if (!nome || !email || !senha) {
            return res.status(400).json({ mensagem: 'Todos os campos precisam ser preenchidos' })
        }

        const senhaCriptografada = await bcrypt.hash(senha, 10)

        const [usuario] = await db.execute(
            'INSERT INTO funcionario (nome,email,senha) VALUES (?,?,?)',
            [nome, email, senhaCriptografada]
        )

        const [retornoUsuario] = await db.execute(
            'SELECT id,nome,email FROM funcionario WHERE id=?',
            [usuario.insertId]
        )

        res.status(201).json(retornoUsuario[0])

    } catch (erro) {
        next(erro)
    }
})

app.post('/login', async (req, res, next) => {
    try {
        const { email, senha } = req.body

        if (!email || !senha) {
            return res.status(400).json({ mensagem: 'Todos os campos precisam ser preenchidos' })
        }

        // Alterado aqui: Adicionado o "id" no SELECT
        const [usuario] = await db.execute(
            'SELECT id, nome, email, senha FROM funcionario WHERE email=?',
            [email]
        )

        if (!usuario[0]) {
            return res.status(404).json({ mensagem: 'Usuário não encontrado' })
        }

        const senhaCorreta = await bcrypt.compare(senha, usuario[0].senha)

        if (!senhaCorreta) {
            return res.status(401).json({ mensagem: 'Usuário não autenticado' })
        }

        // Agora o usuario[0].id vai existir e não será undefined!
        const token = jwt.sign(
            { id: usuario[0].id, email: usuario[0].email },
            JWT_SECRET,
            { expiresIn: '1d' }
        )

        res.json({ token: token })

    } catch (erro) {
        next(erro)
    }
})

app.put('/funcionario/:id', async (req, res, next) => {
    try {
        const { nome, email, senha } = req.body
        const id = req.params.id

        const [verificarFuncionario] = await db.execute(
            'SELECT id,nome,email FROM funcionario WHERE id=? ',
            [id]
        )

        if (!verificarFuncionario[0]) {
            return res.status(404).json({ mensagem: 'Funcionario não encontrado' })
        }
        const senhaCriptografada = await bcrypt.hash(senha, 10)

        const [funcionario] = await db.execute(
            'UPDATE funcionario SET nome=?, email=?, senha=? WHERE id=?',
            [nome, email, senhaCriptografada, id]
        )

        const [retornarFuncionario] = await db.execute(
            'SELECT nome,email FROM funcionario WHERE id=?',
            [id]
        )

        res.status(201).json(retornarFuncionario[0])

    } catch (erro) {
        next(erro)
    }
})


app.delete('/funcionario/:id', async (req, res, next) => {
    try {
        const id = req.params.id

        const [verificarFuncionario] = await db.execute(
            'SELECT id,nome,email FROM funcionario WHERE id=? ',
            [id]
        )

        if (!verificarFuncionario[0]) {
            return res.status(404).json({ mensagem: 'Funcionario não encontrado' })
        }
        const [funcionario] = await db.execute(
            'DELETE FROM funcionario WHERE id=?',
            [id]
        )
        res.status(200).json({ mensagem: 'Usuário deletado com sucesso!' })

    } catch (erro) {
        next(erro)
    }
})



app.post('/produto', autenticar, async (req, res, next) => {
    try {
        const { nome, descricao, preco, quantidade } = req.body
        const funcionario_id = req.usuario.id // Agora vira o ID correto vindo do JWT

        if (!nome || !preco || !quantidade) {
            return res.status(400).json({ mensagem: 'Os campos são obrigatórios' })
        }

        // O segredo está no "descricao ?? null" ali embaixo
        const [produto] = await db.execute(
            'INSERT INTO produto (nome,descricao,preco,quantidade,funcionario_id) VALUES (?,?,?,?,?)',
            [nome, descricao ?? null, preco, quantidade, funcionario_id]
        )

        const [verificarProduto] = await db.execute(
            'SELECT * FROM produto WHERE id_produto=?',
            [produto.insertId]
        )

        res.status(201).json(verificarProduto[0])

    } catch (erro) {
        next(erro)
    }
})


app.put('/produto/:id', autenticar, async (req, res, next) => {
    try {
        const { nome, descricao, preco, quantidade } = req.body
        const id = req.params.id
        const funcionario_id = req.usuario.id

        const [verificarProduto] = await db.execute(
            'SELECT * FROM produto WHERE id_produto=? ',
            [id]
        )

        if (!verificarProduto[0]) {
            return res.status(404).json({ mensagem: 'Produto não encontrado' })
        }

        const nomeNovo = nome || verificarProduto[0].nome
        const descricaoNova = descricao || verificarProduto[0].descricao
        const precoNovo = preco || verificarProduto[0].preco
        const quantidadeNova = quantidade || verificarProduto[0].quantidade

        const [produto] = await db.execute(
            'UPDATE produto SET nome=?, descricao=?, preco=?, quantidade=? WHERE id_produto=?',
            [nomeNovo, descricaoNova, precoNovo, quantidadeNova, id]
        )

        const [retornarProduto] = await db.execute(
            'SELECT * FROM produto WHERE id_produto=?',
            [id]
        )

        res.status(201).json(retornarProduto[0])

    } catch (erro) {
        next(erro)
    }
})

app.delete('/produto/:id', autenticar, async (req, res, next) => {
    try {
        const id = req.params.id

        const [verificarProduto] = await db.execute(
            'SELECT * FROM produto WHERE id_produto=? ',
            [id]
        )

        if (!verificarProduto[0]) {
            return res.status(404).json({ mensagem: 'Produto não encontrado' })
        }

        const [produto] = await db.execute(
            'DELETE FROM produto WHERE id_produto=?',
            [id]
        )


        res.status(200).json({ mensagem: 'Produto deletado com sucesso!' })

    } catch (erro) {
        next(erro)
    }
})

app.get('/produto/:id', async (req, res, next) => {
    try {
        const id = req.params.id

        const [verificarProduto] = await db.execute(
            'SELECT * FROM produto WHERE id_produto=? ',
            [id]
        )

        if (!verificarProduto[0]) {
            return res.status(404).json({ mensagem: 'Produto não encontrado' })
        }

        const [produto] = await db.execute(
            'SELECT nome,descricao,preco,quantidade FROM produto WHERE id_produto=?',
            [id]
        )


        res.status(200).json(verificarProduto[0])

    } catch (erro) {
        next(erro)
    }
})

app.get('/produto', async (req, res, next) => {
    try {

        const [produto] = await db.execute(
            'SELECT nome,descricao,preco,quantidade FROM produto'
        )


        res.status(200).json(produto)

    } catch (erro) {
        next(erro)
    }
})

iniciar()