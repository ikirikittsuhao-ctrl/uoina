const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const cookieParser = require('cookie-parser');
const path = require('path');
require('dotenv').config();

const app = express();
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);

// ミドルウェアの設定
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// 静的ファイルの配信設定
app.use(express.static(path.join(__dirname, 'public')));
app.use('/layout', express.static(path.join(__dirname, 'layout')));

// 認証状態をチェックするミドルウェア
const checkAuth = async (req, res, next) => {
    const token = req.cookies.sb_access_token;
    if (!token) {
        return res.redirect('/login.html');
    }
    
    const { data: { user }, error } = await supabase.auth.getUser(token);
    if (error || !user) {
        res.clearCookie('sb_access_token');
        return res.redirect('/login.html');
    }
    
    req.user = user;
    next();
};

// 【API】新規登録 (ユーザー名 + パスワード)
app.post('/api/signup', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).send('ユーザー名とパスワードを入力してください。');
    }
    
    // Supabase Authに合わせるため、内部で仮のメールアドレスを生成
    const fakeEmail = `${username}@sasuty.local`;

    const { data, error } = await supabase.auth.signUp({
        email: fakeEmail,
        password: password,
        options: {
            data: { display_name: username }
        }
    });

    if (error) {
        return res.status(400).send(`新規登録エラー: ${error.message}`);
    }
    res.redirect('/login.html');
});

// 【API】ログイン
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).send('ユーザー名とパスワードを入力してください。');
    }

    const fakeEmail = `${username}@sasuty.local`;

    const { data, error } = await supabase.auth.signInWithPassword({
        email: fakeEmail,
        password: password
    });

    if (error) {
        return res.status(400).send(`ログインエラー: ${error.message}`);
    }
    
    // クッキーにトークンを保存
    res.cookie('sb_access_token', data.session.access_token, {
        httpOnly: true,
        secure: false, // 本番環境(HTTPS)ではtrueを推奨
        maxAge: 1000 * 60 * 60 * 24 // 1日間有効
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

    const username = req.user.user_metadata.display_name || '名無し';

    const { error } = await supabase
        .from('posts')
        .insert([
            { 
                user_id: req.user.id, 
                username: username, 
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
    res.clearCookie('sb_access_token');
    res.redirect('/login.html');
});

// ルートアクセス時の認証制御
app.get('/', checkAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// サーバー起動
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`[sasuty] サーバーが正常に起動しました: http://localhost:${PORT}`);
});
