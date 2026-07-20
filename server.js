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
        console.warn('❌ クッキーに sasuty_user_id がありません');
        return res.redirect('/login.html');
    }
    
    console.log(`✅ クッキーから取得したID: ${userId}`);
    
    // データベースからユーザーを取得
    const { data: usersArray, error } = await supabase
        .from('users')
        .select('id, username, email, created_at')
        .eq('id', userId);

    // エラーが起きたか、ユーザーがDBに存在しない場合
    if (error) {
        console.error(`❌ DB照合エラー:`, error);
        res.clearCookie('sasuty_user_id');
        return res.redirect('/login.html');
    }

    if (!usersArray || usersArray.length === 0) {
        console.warn(`❌ ID "${userId}" に一致するユーザーがDBに見つかりません`);
        res.clearCookie('sasuty_user_id');
        return res.redirect('/login.html');
    }
    
    req.user = usersArray[0];
    console.log(`✅ 認証成功: ユーザー ${req.user.username} (ID: ${req.user.id})`);
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
        
        const { data, error } = await supabase
            .from('users')
            .insert([{ username, email, password_hash: hashedPassword }])
            .select('id, username, email');

        if (error) {
            console.error('❌ 登録エラー:', error);
            if (error.code === '23505') {
                return res.status(400).send('エラー: そのユーザー名またはメールアドレスは既に登録されています。');
            }
            return res.status(400).send(`新規登録エラー: ${error.message}`);
        }

        if (!data || data.length === 0) {
            console.error('❌ 登録後のデータ取得失敗');
            return res.status(500).send('ユーザーデータの登録、またはIDの取得に失敗しました。');
        }

        const registeredUser = data[0];
        console.log(`✅ 新規ユーザー登録完了: ${registeredUser.username} (ID: ${registeredUser.id})`);

        // ✅ 取得したIDを正確にクッキーに保存
        res.cookie('sasuty_user_id', registeredUser.id, { 
            httpOnly: true, 
            secure: false,  // 本番環境では true に変更
            maxAge: 1000 * 60 * 60 * 24,
            sameSite: 'Lax'
        });

        console.log(`✅ クッキーに保存されたID: ${registeredUser.id}`);
        res.redirect('/');
    } catch (err) {
        console.error('❌ サーバー内部エラー:', err);
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
        .select('id, username, password_hash')
        .eq('username', username);

    if (error) {
        console.error('❌ ユーザー検索エラー:', error);
        return res.status(400).send('ログインエラー: ユーザー名またはパスワードが違います。');
    }

    if (!usersArray || usersArray.length === 0) {
        console.warn(`❌ ユーザー名 "${username}" が見つかりません`);
        return res.status(400).send('ログインエラー: ユーザー名またはパスワードが違います。');
    }

    const user = usersArray[0];

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
        console.warn(`❌ パスワード不一致: ${username}`);
        return res.status(400).send('ログインエラー: ユーザー名またはパスワードが違います。');
    }
    
    console.log(`✅ ログイン成功: ${username} (ID: ${user.id})`);
    
    res.cookie('sasuty_user_id', user.id, { 
        httpOnly: true, 
        secure: false,  // 本番環境では true に変更
        maxAge: 1000 * 60 * 60 * 24,
        sameSite: 'Lax'
    });
    
    console.log(`✅ クッキーに保存されたID: ${user.id}`);
    res.redirect('/');
});

// 【API】投稿一覧取得
app.get('/api/posts', async (req, res) => {
    const { data, error } = await supabase
        .from('posts')
        .select('*')
        .order('created_at', { ascending: false });
    
    if (error) {
        console.error('❌ 投稿一覧取得エラー:', error);
        return res.status(500).json({ error: error.message });
    }
    res.json(data);
});

// 【API】新規投稿作成
app.post('/api/posts', checkAuth, async (req, res) => {
    const { content } = req.body;
    if (!content || content.trim() === '') {
        return res.status(400).send('投稿内容が空です。');
    }

    const userId = req.user.id;
    const username = req.user.username;

    console.log(`📝 投稿試行: user_id=${userId}, username=${username}`);

    const { data, error } = await supabase
        .from('posts')
        .insert([{ 
            user_id: userId, 
            username: username, 
            content: content 
        }])
        .select('id, user_id');

    if (error) {
        console.error(`❌ 投稿エラー (外部キー制約):`, error);
        console.error(`   user_id: ${userId}`);
        console.error(`   エラー詳細:`, error.message);
        return res.status(500).send(`投稿エラー: ${error.message}`);
    }

    console.log(`✅ 投稿作成完了: ID=${data[0].id}`);
    res.redirect('/');
});

// 【API】ログアウト
app.get('/api/logout', (req, res) => {
    console.log('🚪 ログアウト実行');
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
