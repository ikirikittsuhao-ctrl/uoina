const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const path = require('path');
const https = require('https');
const http = require('http');
require('dotenv').config();

if (!process.env.SUPABASE_URL || !process.env.SUPABASE_ANON_KEY) {
    console.error('【致命的なエラー】環境変数 SUPABASE_URL または SUPABASE_ANON_KEY が設定されていません。');
    process.exit(1);
}

const app = express();
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use(express.static(path.join(__dirname, 'public')));
app.use('/layout', express.static(path.join(__dirname, 'layout')));

// 【認証ミドルウェア】
const checkAuth = async (req, res, next) => {
    const userId = req.cookies.sasuty_user_id;
    if (!userId) return res.redirect('/login.html');

    const { data: usersArray, error } = await supabase
        .from('users')
        .select('*')
        .eq('id', userId);

    if (error || !usersArray || usersArray.length === 0) {
        res.clearCookie('sasuty_user_id');
        return res.redirect('/login.html');
    }

    req.user = usersArray[0];
    next();
};

// 【画像プロキシ機能】CORS対策・セキュアな画像の読み込み用
app.get('/api/proxy-image', (req, res) => {
    const imageUrl = req.query.url;
    if (!imageUrl) return res.status(400).send('URL is required');

    try {
        const parsedUrl = new URL(imageUrl);
        const protocol = parsedUrl.protocol === 'https:' ? https : http;

        protocol.get(imageUrl, (response) => {
            if (response.statusCode !== 200) {
                return res.status(response.statusCode).send('Failed to fetch image');
            }
            res.setHeader('Content-Type', response.headers['content-type'] || 'image/jpeg');
            response.pipe(res);
        }).on('error', () => {
            res.status(500).send('Image fetch error');
        });
    } catch (e) {
        res.status(400).send('Invalid URL');
    }
});

// 【API】新規登録
app.post('/api/signup', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.status(400).send('すべての項目を入力してください。');

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const { data, error } = await supabase
            .from('users')
            .insert([{ username, email, password_hash: hashedPassword }])
            .select('*');

        if (error) return res.status(400).send(`登録エラー: ${error.message}`);
        
        res.cookie('sasuty_user_id', data[0].id, {
            httpOnly: true,
            maxAge: 1000 * 60 * 60 * 24 * 30,
            sameSite: 'Lax'
        });
        res.redirect('/');
    } catch (err) {
        res.status(500).send('サーバーエラーが発生しました。');
    }
});

// 【API】ログイン
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).send('入力してください。');

    const { data: usersArray, error } = await supabase
        .from('users')
        .select('*')
        .eq('username', username);

    if (error || !usersArray || usersArray.length === 0) {
        return res.status(400).send('ユーザー名またはパスワードが違います。');
    }

    const user = usersArray[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(400).send('ユーザー名またはパスワードが違います。');

    res.cookie('sasuty_user_id', user.id, {
        httpOnly: true,
        maxAge: 1000 * 60 * 60 * 24 * 30,
        sameSite: 'Lax'
    });
    res.redirect('/');
});

// 【API】現在ログイン中のユーザー情報取得
app.get('/api/me', checkAuth, (req, res) => {
    const { password_hash, ...userInfo } = req.user;
    res.json(userInfo);
});

// 【API】投稿一覧取得 (閲覧数の加算処理も含む)
app.get('/api/posts', checkAuth, async (req, res) => {
    const currentUserId = req.user.id;

    // 投稿と投稿者情報を取得
    const { data: posts, error } = await supabase
        .from('posts')
        .select(`
            *,
            users:user_id (id, username, avatar_url)
        `)
        .order('created_at', { ascending: false });

    if (error) return res.status(500).json({ error: error.message });

    // 自分のいいね・リポスト状態の確認
    const { data: myLikes } = await supabase.from('likes').select('post_id').eq('user_id', currentUserId);
    const { data: myReposts } = await supabase.from('reposts').select('post_id').eq('user_id', currentUserId);

    const likedPostIds = new Set((myLikes || []).map(l => l.post_id));
    const repostedPostIds = new Set((myReposts || []).map(r => r.post_id));

    // タイムライン取得に伴い閲覧数を+1（バックグラウンドで一括更新）
    const postIds = posts.map(p => p.id);
    if (postIds.length > 0) {
        for (let p of posts) {
            await supabase.from('posts').update({ views_count: (p.views_count || 0) + 1 }).eq('id', p.id);
        }
    }

    const formattedPosts = posts.map(post => ({
        ...post,
        views_count: (post.views_count || 0) + 1,
        isLiked: likedPostIds.has(post.id),
        isReposted: repostedPostIds.has(post.id)
    }));

    res.json(formattedPosts);
});

// 【API】新規投稿作成
app.post('/api/posts', checkAuth, async (req, res) => {
    const { content } = req.body;
    if (!content || !content.trim()) return res.status(400).send('投稿内容が空です。');

    const { error } = await supabase
        .from('posts')
        .insert([{ user_id: req.user.id, username: req.user.username, content }]);

    if (error) return res.status(500).send(`投稿エラー: ${error.message}`);
    res.redirect('/');
});

// 【API】いいね Toggle
app.post('/api/posts/:id/like', checkAuth, async (req, res) => {
    const postId = req.params.id;
    const userId = req.user.id;

    const { data: existing } = await supabase.from('likes').select('id').eq('post_id', postId).eq('user_id', userId).single();

    if (existing) {
        await supabase.from('likes').delete().eq('id', existing.id);
        const { data: post } = await supabase.from('posts').select('likes_count').eq('id', postId).single();
        const newCount = Math.max(0, (post.likes_count || 1) - 1);
        await supabase.from('posts').update({ likes_count: newCount }).eq('id', postId);
        res.json({ liked: false, likes_count: newCount });
    } else {
        await supabase.from('likes').insert([{ post_id: postId, user_id: userId }]);
        const { data: post } = await supabase.from('posts').select('likes_count').eq('id', postId).single();
        const newCount = (post.likes_count || 0) + 1;
        await supabase.from('posts').update({ likes_count: newCount }).eq('id', postId);
        res.json({ liked: true, likes_count: newCount });
    }
});

// 【API】リポスト Toggle
app.post('/api/posts/:id/repost', checkAuth, async (req, res) => {
    const postId = req.params.id;
    const userId = req.user.id;

    const { data: existing } = await supabase.from('reposts').select('id').eq('post_id', postId).eq('user_id', userId).single();

    if (existing) {
        await supabase.from('reposts').delete().eq('id', existing.id);
        const { data: post } = await supabase.from('posts').select('reposts_count').eq('id', postId).single();
        const newCount = Math.max(0, (post.reposts_count || 1) - 1);
        await supabase.from('posts').update({ reposts_count: newCount }).eq('id', postId);
        res.json({ reposted: false, reposts_count: newCount });
    } else {
        await supabase.from('reposts').insert([{ post_id: postId, user_id: userId }]);
        const { data: post } = await supabase.from('posts').select('reposts_count').eq('id', postId).single();
        const newCount = (post.reposts_count || 0) + 1;
        await supabase.from('posts').update({ reposts_count: newCount }).eq('id', postId);
        res.json({ reposted: true, reposts_count: newCount });
    }
});

// 【API】特定ユーザーのプロフィール取得
app.get('/api/users/:username', checkAuth, async (req, res) => {
    const { data: targetUser, error } = await supabase
        .from('users')
        .select('id, username, avatar_url, banner_url, bio, website, birthday, created_at')
        .eq('username', req.params.username)
        .single();

    if (error || !targetUser) return res.status(404).json({ error: 'ユーザーが見つかりません' });

    // 対象ユーザーの投稿一覧を取得
    const { data: userPosts } = await supabase
        .from('posts')
        .select(`*, users:user_id (id, username, avatar_url)`)
        .eq('user_id', targetUser.id)
        .order('created_at', { ascending: false });

    res.json({ user: targetUser, posts: userPosts || [] });
});

// 【API】プロフィール更新
app.post('/api/profile/update', checkAuth, async (req, res) => {
    const { avatar_url, banner_url, bio, website, birthday } = req.body;
    
    const { error } = await supabase
        .from('users')
        .update({ avatar_url, banner_url, bio, website, birthday })
        .eq('id', req.user.id);

    if (error) return res.status(500).send('更新エラー');
    res.redirect('/profile.html');
});

// 【API】ログアウト
app.get('/api/logout', (req, res) => {
    res.clearCookie('sasuty_user_id');
    res.redirect('/login.html');
});

app.get('/', checkAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/profile.html', checkAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'profile.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
