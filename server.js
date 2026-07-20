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
    
    // データベースからユーザーを取得
    const { data: user, error } = await supabase
        .from('users')
        .select('*')
        .eq('id', userId)
        .maybeSingle();

    // エラーが起きたか、ユーザーがDBに存在しない場合（ここが重要）
    if (error || !user) {
        // 不正なIDや古いIDが入っているクッキーを完全に消去する
        res.clearCookie('sasuty_user_id');
        return res.redirect('/login.html');
    }
    
    req.user = user;
    next();
};

// 【API】新規登録 (自動ログインするように修正)
app.post('/api/signup', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
        return res.status(400).send('すべての項目を入力してください。');
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // .select() を末尾につけて、生成されたばかりの正しいUUIDをDBから返してもらう
        const { data: newUser, error } = await supabase
            .from('users')
            .insert([{ username, email, password_hash: hashedPassword }])
            .select()
            .maybeSingle();

        if (error) {
            if (error.code === '23505') {
                return res.status(400).send('エラー: そのユーザー名またはメールアドレスは既に登録されています。');
            }
            return res.status(400).send(`新規登録エラー: ${error.message}`);
        }

        if (!newUser) {
            return res.status(500).send('ユーザーデータの生成に失敗しました。');
        }

        // 登録完了後、別のログイン手順を踏ませず、その正しいUUIDで即クッキーを焼いてログイン状態にする
        res.cookie('sasuty_user_id', newUser.id, { 
            httpOnly: true, 
            secure: false,
            maxAge: 1000 * 60 * 60 * 24 
        });

        // ログイン画面ではなくホーム画面に直接リダイレクト
        res.redirect('/');
    } catch (err) {
        res.status(500).send('サーバー内部エラーが発生しました。');
    }
});

// 【API】ログイン
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).send('ユーザー名とパスワードを入力してください。');
    }

    const { data: user, error } = await supabase
        .from('users')
        .select('*')
        .eq('username', username)
        .maybeSingle();

    if (error || !user) {
        return res.status(400).send('ログインエラー: ユーザー名またはパスワードが違います。');
    }

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
        return res.status(400).send('ログインエラー: ユーザー名またはパスワードが違います。');
    }
    
    // クッキーにログインの証拠としてユーザーIDを保存
    res.cookie('sasuty_user_id', user.id, { 
        httpOnly: true, 
        secure: false,
        maxAge: 1000 * 60 * 60 * 24 
    });
    
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

    // 念のため再チェック
    if (!req.user || !req.user.id) {
        return res.status(401).send('認証エラー: もう一度ログインし直してください。');
    }

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
