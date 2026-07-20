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
    
    const { data: usersArray, error } = await supabase
        .from('users')
        .select('id, username, email, created_at')
        .eq('id', userId);

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

// 【API】新規登録
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

        // ✅ 登録が確実に反映されるまで待機
        await new Promise(resolve => setTimeout(resolve, 500));

        // 🔍 登録直後に同じIDで再度照合
        const { data: verifyData, error: verifyError } = await supabase
            .from('users')
            .select('id, username')
            .eq('id', registeredUser.id);

        if (verifyError || !verifyData || verifyData.length === 0) {
            console.error('❌ 登録直後の照合失敗 - ユーザーがDB上に見当たりません');
            return res.status(500).send('ユーザー登録の確認に失敗しました。もう一度お試しください。');
        }

        console.log(`✅ 登録検証成功: ユーザーはDBに確実に存在`);

        res.cookie('sasuty_user_id', registeredUser.id, { 
            httpOnly: true, 
            secure: false,
            maxAge: 1000 * 60 * 60 * 24,
            sameSite: 'Lax'
        });

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
        secure: false,
        maxAge: 1000 * 60 * 60 * 24,
        sameSite: 'Lax'
    });
    
    res.redirect('/');
});

// 【API】投稿一覧取得（いいね・リポスト情報付き）
app.get('/api/posts', checkAuth, async (req, res) => {
    try {
        const { data: posts, error } = await supabase
            .from('posts')
            .select(`
                id,
                user_id,
                username,
                content,
                created_at,
                view_count,
                repost_count,
                like_count
            `)
            .order('created_at', { ascending: false });
        
        if (error) {
            console.error('❌ 投稿一覧取得エラー:', error);
            return res.status(500).json({ error: error.message });
        }

        // 現在のユーザーが各投稿にいいねしているか、リポストしているかを確認
        const postsWithUserState = await Promise.all(posts.map(async (post) => {
            const { data: likeData } = await supabase
                .from('likes')
                .select('id')
                .eq('post_id', post.id)
                .eq('user_id', req.user.id);

            const { data: repostData } = await supabase
                .from('reposts')
                .select('id')
                .eq('post_id', post.id)
                .eq('user_id', req.user.id);

            return {
                ...post,
                is_liked: likeData && likeData.length > 0,
                is_reposted: repostData && repostData.length > 0
            };
        }));

        res.json(postsWithUserState);
    } catch (err) {
        console.error('❌ エラー:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
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
            content: content,
            view_count: 0,
            repost_count: 0,
            like_count: 0
        }])
        .select('id, user_id');

    if (error) {
        console.error(`❌ 投稿エラー:`, error);
        return res.status(500).send(`投稿エラー: ${error.message}`);
    }

    console.log(`✅ 投稿作成完了: ID=${data[0].id}`);
    res.redirect('/');
});

// 【API】いいね追加
app.post('/api/posts/:postId/like', checkAuth, async (req, res) => {
    const { postId } = req.params;
    const userId = req.user.id;

    console.log(`❤️ いいね試行: post_id=${postId}, user_id=${userId}`);

    // いいねを追加
    const { error: insertError } = await supabase
        .from('likes')
        .insert([{ post_id: postId, user_id: userId }]);

    if (insertError) {
        if (insertError.code === '23505') {
            return res.status(400).json({ error: 'すでにいいねしています' });
        }
        console.error('❌ いいね追加エラー:', insertError);
        return res.status(500).json({ error: insertError.message });
    }

    // いいね数をインクリメント
    const { error: updateError } = await supabase
        .from('posts')
        .update({ like_count: supabase.raw('like_count + 1') })
        .eq('id', postId);

    if (updateError) {
        console.error('❌ いいね数更新エラー:', updateError);
        return res.status(500).json({ error: updateError.message });
    }

    console.log(`✅ いいね完了: post_id=${postId}`);
    res.json({ success: true });
});

// 【API】いいね削除
app.delete('/api/posts/:postId/like', checkAuth, async (req, res) => {
    const { postId } = req.params;
    const userId = req.user.id;

    console.log(`💔 いいね削除試行: post_id=${postId}, user_id=${userId}`);

    // いいねを削除
    const { error: deleteError } = await supabase
        .from('likes')
        .delete()
        .eq('post_id', postId)
        .eq('user_id', userId);

    if (deleteError) {
        console.error('❌ いいね削除エラー:', deleteError);
        return res.status(500).json({ error: deleteError.message });
    }

    // いいね数をデクリメント
    const { error: updateError } = await supabase
        .from('posts')
        .update({ like_count: supabase.raw('like_count - 1') })
        .eq('id', postId);

    if (updateError) {
        console.error('❌ いいね数更新エラー:', updateError);
        return res.status(500).json({ error: updateError.message });
    }

    console.log(`✅ いいね削除完了: post_id=${postId}`);
    res.json({ success: true });
});

// 【API】リポスト追加
app.post('/api/posts/:postId/repost', checkAuth, async (req, res) => {
    const { postId } = req.params;
    const userId = req.user.id;

    console.log(`🔄 リポスト試行: post_id=${postId}, user_id=${userId}`);

    const { error: insertError } = await supabase
        .from('reposts')
        .insert([{ post_id: postId, user_id: userId }]);

    if (insertError) {
        if (insertError.code === '23505') {
            return res.status(400).json({ error: 'すでにリポストしています' });
        }
        console.error('❌ リポスト追加エラー:', insertError);
        return res.status(500).json({ error: insertError.message });
    }

    const { error: updateError } = await supabase
        .from('posts')
        .update({ repost_count: supabase.raw('repost_count + 1') })
        .eq('id', postId);

    if (updateError) {
        console.error('❌ リポスト数更新エラー:', updateError);
        return res.status(500).json({ error: updateError.message });
    }

    console.log(`✅ リポスト完了: post_id=${postId}`);
    res.json({ success: true });
});

// 【API】リポスト削除
app.delete('/api/posts/:postId/repost', checkAuth, async (req, res) => {
    const { postId } = req.params;
    const userId = req.user.id;

    console.log(`🔄 リポスト削除試行: post_id=${postId}, user_id=${userId}`);

    const { error: deleteError } = await supabase
        .from('reposts')
        .delete()
        .eq('post_id', postId)
        .eq('user_id', userId);

    if (deleteError) {
        console.error('❌ リポスト削除エラー:', deleteError);
        return res.status(500).json({ error: deleteError.message });
    }

    const { error: updateError } = await supabase
        .from('posts')
        .update({ repost_count: supabase.raw('repost_count - 1') })
        .eq('id', postId);

    if (updateError) {
        console.error('❌ リポスト数更新エラー:', updateError);
        return res.status(500).json({ error: updateError.message });
    }

    console.log(`✅ リポスト削除完了: post_id=${postId}`);
    res.json({ success: true });
});

// 【API】プロフィール取得
app.get('/api/users/:username', async (req, res) => {
    const { username } = req.params;

    try {
        const { data: userData, error: userError } = await supabase
            .from('users')
            .select('id, username, created_at')
            .eq('username', username);

        if (userError || !userData || userData.length === 0) {
            return res.status(404).json({ error: 'ユーザーが見つかりません' });
        }

        const user = userData[0];

        const { data: profileData, error: profileError } = await supabase
            .from('profiles')
            .select('bio, avatar_url, cover_url, followers_count, following_count')
            .eq('user_id', user.id);

        if (profileError) {
            console.error('❌ プロフィール取得エラー:', profileError);
            return res.status(500).json({ error: profileError.message });
        }

        const profile = profileData && profileData.length > 0 ? profileData[0] : {};

        // ユーザーの投稿数を取得
        const { data: postsData, error: postsError } = await supabase
            .from('posts')
            .select('id')
            .eq('user_id', user.id);

        const postCount = postsData ? postsData.length : 0;

        res.json({
            id: user.id,
            username: user.username,
            created_at: user.created_at,
            bio: profile.bio || '',
            avatar_url: profile.avatar_url || null,
            cover_url: profile.cover_url || null,
            followers_count: profile.followers_count || 0,
            following_count: profile.following_count || 0,
            post_count: postCount
        });
    } catch (err) {
        console.error('❌ エラー:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// 【API】プロフィール更新
app.put('/api/users/:userId/profile', checkAuth, async (req, res) => {
    const { userId } = req.params;
    const { bio, avatar_url, cover_url } = req.body;

    // 本人確認
    if (req.user.id !== userId) {
        return res.status(403).json({ error: '他のユーザーのプロフィールは編集できません' });
    }

    try {
        const { error } = await supabase
            .from('profiles')
            .update({ bio, avatar_url, cover_url })
            .eq('user_id', userId);

        if (error) {
            console.error('❌ プロフィール更新エラー:', error);
            return res.status(500).json({ error: error.message });
        }

        console.log(`✅ プロフィール更新完了: user_id=${userId}`);
        res.json({ success: true });
    } catch (err) {
        console.error('❌ エラー:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// 【API】現在のユーザー情報取得
app.get('/api/user-info', checkAuth, (req, res) => {
    res.json({
        id: req.user.id,
        username: req.user.username,
        email: req.user.email
    });
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
