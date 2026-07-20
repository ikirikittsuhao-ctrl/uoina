const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const path = require('path');
require('dotenv').config();

const app = express();
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use(express.static(path.join(__dirname, 'public')));
app.use('/layout', express.static(path.join(__dirname, 'layout')));

// 【カスタム認証ミドルウェア】
const checkAuth = async (req, res, next) => {
    const userId = req.cookies.sasuty_user_id;
    if (!userId) {
        return res.redirect('/login.html');
    }
    
    const { data: user, error } = await supabase
        .from('users')
        .select('*')
        .eq('id', userId)
        .maybeSingle();

    if (error || !user) {
        res.clearCookie('sasuty_user_id');
        return res.redirect('/login.html');
    }
    
    req.user = user;
    next();
};

// 【API】新規登録
app.post('/api/signup', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
        return res.status(400).send('すべての項目を入力してください。');
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const { error } = await supabase
            .from('users')
            .insert([{ username, email, password_hash: hashedPassword }]);

        if (error) {
            return res.status(400).send(`新規登録エラー: ${error.message}`);
        }
        res.redirect('/login.html');
    } catch (err) {
        res.status(500).send('サーバー内部エラーが発生しました。');
    }
});

// 【API】ログイン
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const { data: user, error } = await supabase
        .from('users')
        .select('*')
        .eq('username', username)
        .maybeSingle();

    if (error || !user) {
        return res.status(400).send('ログインエラー: ユーザーが見つかりません。');
    }

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
        return res.status(400).send('ログインエラー: パスワードが違います。');
    }
    
    res.cookie('sasuty_user_id', user.id, { httpOnly: true, maxAge: 1000 * 60 * 60 * 24 });
    res.redirect('/');
});

// 【API】投稿一覧取得
app.get('/api/posts', async (req, res) => {
    const { data, error } = await supabase
        .from('posts')
        .select('*')
        .order('created_at', { ascending: false });
    
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
});

// 【API】新規投稿作成
app.post('/api/posts', checkAuth, async (req, res) => {
    const { content } = req.body;
    if (!content || content.trim() === '') return res.status(400).send('投稿内容が空です。');

    const { error } = await supabase
        .from('posts')
        .insert([{ 
            user_id: req.user.id, 
            username: req.user.username, 
            content: content 
        }]);

    if (error) return res.status(500).send(`投稿エラー: ${error.message}`);
    res.redirect('/');
});

// 【API】ログアウト
app.get('/api/logout', (req, res) => {
    res.clearCookie('sasuty_user_id');
    res.redirect('/login.html');
});

app.get('/', checkAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`サーバー起動: http://localhost:${PORT}`);
});
