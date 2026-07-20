const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const path = require('path');
require('dotenv').config();

// 環境変数のチェック
if (!process.env.SUPABASE_URL || !process.env.SUPABASE_ANON_KEY) {
    console.error('【致命的なエラー】環境変数 SUPABASE_URL または SUPABASE_ANON_KEY が設定されていません。');
    console.error('Renderの「Environment」設定、またはローカルの .env ファイルを確認してください。');
    process.exit(1);
}

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
    const { data: usersArray, error } = await supabase
        .from('users')
        .select('*')
        .eq('id', userId);

    // エラーが起きたか、ユーザーがDBに存在しない場合
    if (error || !usersArray || usersArray.length === 0) {
        res.clearCookie('sasuty_user_id');
        return res.redirect('/login.html');
    }
    
    req.user = usersArray[0]; // 確実に配列の1件目を取得
    next();
};

// 【API】新規登録 (自動ログイン仕様・確実なデータ抽出)
app.post('/api/signup', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
        return res.status(400).send('すべての項目を入力してください。');
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // 末尾を .select() のみにして確実に入記直後のデータ配列を返してもらう
        const { data, error } = await supabase
            .from('users')
            .insert([{ username, email, password_hash: hashedPassword }])
            .select();

        if (error) {
            if (error.code === '23505') {
                return res.status(400).send('エラー: そのユーザー名またはメールアドレスは既に登録されています。');
            }
            return res.status(400).send(`新規登録エラー: ${error.message}`);
        }

        // 配列が空、またはデータが取れていない場合のガード
        if (!data || data.length === 0) {
            return res.status(500).send('ユーザーデータの登録、またはIDの取得に失敗しました。');
        }

        // 配列の最初の要素から、Supabaseが自動生成した本当のUUIDを取り出す
        const registeredUser = data[0];

        // 登録された本物のIDをクッキーに保存して自動ログイン
        res.cookie('sasuty_user_id', registeredUser.id, { 
            httpOnly: true, 
            secure: false,
            maxAge: 1000 * 60 * 60 * 24 
        });

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

    const { data: usersArray, error } = await supabase
        .from('users')
        .select('*')
        .eq('username', username);

    if (error || !usersArray || usersArray.length === 0) {
        return res.status(400).send('ログインエラー: ユーザー名またはパスワードが違います。');
    }

    const user = usersArray[0]; // 配列からユーザーデータを抽出

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
        return res.status(400).send('ログインエラー: ユーザー名またはパスワードが違います。');
    }
    
    // クッキーにログインの証拠としてユーザーID（UUID）を正確に保存
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

    // 認証ミドルウェアを通過した直後のIDを再確認
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
