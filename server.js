const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const path = require('path');
const app = express();

// 中间件
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// 初始化数据库
const db = new sqlite3.Database('blog.db');

// 创建文章表
db.run(`
    CREATE TABLE IF NOT EXISTS articles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        author TEXT NOT NULL,
        content TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
`);

// 路由

// 首页
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// 创建文章页面
app.get('/create', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'create.html'));
});

// 获取所有文章列表
app.get('/api/articles', (req, res) => {
    db.all(`
        SELECT id, title, author, created_at 
        FROM articles 
        ORDER BY created_at DESC
    `, (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json(rows);
    });
});

// 创建文章
app.post('/api/articles', async (req, res) => {
    const { title, author, content, password, confirmPassword } = req.body;
    
    // 验证输入
    if (!title || !author || !content || !password) {
        return res.status(400).json({ error: '所有字段都必须填写' });
    }
    
    if (password !== confirmPassword) {
        return res.status(400).json({ error: '两次输入的密码不一致' });
    }
    
    if (password.length < 6) {
        return res.status(400).json({ error: '密码长度至少6位' });
    }
    
    if (title.length > 100) {
        return res.status(400).json({ error: '标题长度不能超过100字符' });
    }
    
    if (author.length > 50) {
        return res.status(400).json({ error: '作者名称不能超过50字符' });
    }
    
    if (content.length > 10000) {
        return res.status(400).json({ error: '正文不能超过10000字符' });
    }
    
    try {
        // 加密密码
        const passwordHash = await bcrypt.hash(password, 10);
        
        // 插入数据库
        db.run(`
            INSERT INTO articles (title, author, content, password_hash)
            VALUES (?, ?, ?, ?)
        `, [title, author, content, passwordHash], function(err) {
            if (err) {
                res.status(500).json({ error: err.message });
                return;
            }
            res.json({ 
                success: true, 
                message: '文章创建成功',
                id: this.lastID 
            });
        });
    } catch (error) {
        res.status(500).json({ error: '服务器错误' });
    }
});

// 验证密码并获取文章
app.post('/api/articles/:id/verify', async (req, res) => {
    const { password } = req.body;
    const articleId = req.params.id;
    
    if (!password) {
        return res.status(400).json({ error: '请输入密码' });
    }
    
    db.get(`
        SELECT * FROM articles WHERE id = ?
    `, [articleId], async (err, row) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        
        if (!row) {
            res.status(404).json({ error: '文章不存在' });
            return;
        }
        
        try {
            // 验证密码
            const isValid = await bcrypt.compare(password, row.password_hash);
            
            if (!isValid) {
                res.status(401).json({ error: '密码错误' });
                return;
            }
            
            // 返回文章内容（不包含密码哈希）
            const { password_hash, ...article } = row;
            res.json({ success: true, article });
        } catch (error) {
            res.status(500).json({ error: '服务器错误' });
        }
    });
});

// 更新文章
app.put('/api/articles/:id', async (req, res) => {
    const { title, author, content, password } = req.body;
    const articleId = req.params.id;
    
    if (!title || !author || !content || !password) {
        return res.status(400).json({ error: '所有字段都必须填写' });
    }
    
    // 首先验证密码
    db.get(`
        SELECT password_hash FROM articles WHERE id = ?
    `, [articleId], async (err, row) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        
        if (!row) {
            res.status(404).json({ error: '文章不存在' });
            return;
        }
        
        try {
            const isValid = await bcrypt.compare(password, row.password_hash);
            
            if (!isValid) {
                res.status(401).json({ error: '密码错误' });
                return;
            }
            
            // 更新文章
            db.run(`
                UPDATE articles 
                SET title = ?, author = ?, content = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            `, [title, author, content, articleId], function(err) {
                if (err) {
                    res.status(500).json({ error: err.message });
                    return;
                }
                res.json({ success: true, message: '文章更新成功' });
            });
        } catch (error) {
            res.status(500).json({ error: '服务器错误' });
        }
    });
});

// 删除文章
app.delete('/api/articles/:id', (req, res) => {
    const articleId = req.params.id;
    
    db.run(`
        DELETE FROM articles WHERE id = ?
    `, [articleId], function(err) {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        
        if (this.changes === 0) {
            res.status(404).json({ error: '文章不存在' });
            return;
        }
        
        res.json({ success: true, message: '文章删除成功' });
    });
});

// 启动服务器
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`服务器运行在 http://localhost:${PORT}`);
});

// 优雅关闭
process.on('SIGINT', () => {
    db.close((err) => {
        if (err) {
            console.error(err.message);
        }
        console.log('数据库连接已关闭');
        process.exit(0);
    });
});