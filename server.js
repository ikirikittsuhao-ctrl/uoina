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

// 【カスタム認証ミドルウェア】クッキーのユーザーIDからユーザー実在チェック
const checkAuth = async (req, res, next) => {
    const userId = req.cookies.sasuty_user_id;
    if (!userId) {
        return res.redirect('/login.html');
    }
    
    // データベースからユーザーを取得
    const { data: user, error } = await supabase
        .from('users')
        .select('*')
        .eq('id', userId)
        .single();

    if (error || !user) {
        res.clearCookie('sasuty_user_id');
        return res.redirect('/login.html');
    }
    
    req.user = user; // 後続の処理でユーザー情報を使えるように保持
    next();
};

// 【API】独自 新規登録 (usersテーブルへ直接保存)
app.post('/api/signup', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
        return res.status(400).send('すべての項目を入力してください。');
    }

    try {
        // パスワードをハッシュ化（10ソルトハッシュ）
        const hashedPassword = await bcrypt.hash(password, 10);

        // 自前のusersテーブルへインサート
        const { data, error } = await supabase
            .from('users')
            .insert([
                { username, email, password_hash: hashedPassword }
            ]);

        if (error) {
            if (error.code === '23505') { // PostgreSQLの重複エラーコード
                return res.status(400).send('エラー: そのユーザー名またはメールアドレスは既に登録されています。');
            }
            return res.status(400).send(`新規登録エラー: ${error.message}`);
        }

        res.redirect('/login.html');
    } catch (err) {
        res.status(500).send('サーバー内部エラーが発生しました。');
    }
});

// 【API】独自 ログイン
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).send('ユーザー名とパスワードを入力してください。');
    }

    // ユーザー名でデータベースを検索
    const { data: user, error } = await supabase
        .from('users')
        .select('*')
        .eq('username', username)
        .single();

    if (error || !user) {
        return res.status(400).send('ログインエラー: ユーザー名またはパスワードが違います。');
    }

    // パスワードの照合
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
        return res.status(400).send('ログインエラー: ユーザー名またはパスワードが違います。');
    }
    
    // クッキーにログインの証拠としてユーザーIDを保存
    res.cookie('sasuty_user_id', user.id, {
        httpOnly: true,
        secure: false,
        maxAge: 1000 * 60 * 60 * 24 // 1日間
    });
    
    res.redirect('/');
});

// 【API】投稿一覧の取得
app.get('/api/posts', async (req, res) => {
    const { data, error } = await supabase
        .from('posts')
        .select('*')
        .order('created_at', { ascending: false });
    
    if (error) {
        return res.status(500).json({ error: error.message });
    }
    res.json(data);
});

// 【API】新規投稿の作成
app.post('/api/posts', checkAuth, async (req, res) => {
    const { content } = req.body;
    if (!content || content.trim() === '') {
        return res.status(400).send('投稿内容が空です。');
    }

    const { error } = await supabase
        .from('posts')
        .insert([
            { 
                user_id: req.user.id, 
                username: req.user.username, 
                content: content 
            }
        ]);

    if (error) {
        return res.status(500).send(`投稿エラー: ${error.message}`);
    }
    res.redirect('/');
});

// 【API】ログアウト
app.get('/api/logout', (req, res) => {
    res.clearCookie('sasuty_user_id');
    res.redirect('/login.html');
});

// ルートアクセス制御
app.get('/', checkAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`[sasuty] 独自テーブル認証版サーバー起動: http://localhost:${PORT}`);
});
