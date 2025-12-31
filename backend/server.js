require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const marked = require('marked');
const katex = require('katex');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(helmet());
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// Database connection
let pool;
async function initDB() {
    pool = mysql.createPool({
        host: process.env.DB_HOST,
        port: process.env.DB_PORT || 4000,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME,
        ssl: {
            rejectUnauthorized: true
        },
        waitForConnections: true,
        connectionLimit: 10,
        queueLimit: 0
    });
}


// Auth middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.sendStatus(401);
    
    jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

function isAdmin(req, res, next) {
    if (req.user.role !== 'admin' && req.user.role !== 'super_admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
}

function isSuperAdmin(req, res, next) {
    if (req.user.role !== 'super_admin') {
        return res.status(403).json({ error: 'Super admin access required' });
    }
    next();
}

// 修改 updateVitality 函数定义，添加缺失的参数
async function updateVitality(userId, amount, reason, source_type = null, source_id = null) {
    try {
        await pool.execute(
            'UPDATE users SET vitality = GREATEST(0, vitality + ?) WHERE id = ?',
            [amount, userId]
        );
        
        await pool.execute(
            'INSERT INTO vitality_history (author_id, change_amount, reason, source_type, source_id) VALUES (?, ?, ?, ?, ?)',
            [userId, amount, reason, source_type, source_id]
        );
    } catch (error) {
        console.error('Error updating vitality:', error);
    }
}
// Check weekly vitality decrease
async function checkWeeklyVitalityDecrease() {
    try {
        const [users] = await pool.execute(`
            SELECT id, vitality, updated_at 
            FROM users 
            WHERE role = 'user'
        `);
        
        const oneWeekAgo = new Date();
        oneWeekAgo.setDate(oneWeekAgo.getDate() - 7);
        
        for (const user of users) {
            if (user.updated_at < oneWeekAgo) {
                await updateVitality(user.id, -1, 'weekly_decrease');
            }
        }
    } catch (error) {
        console.error('Error checking weekly vitality:', error);
    }
}

// Schedule weekly vitality check (run daily)
setInterval(checkWeeklyVitalityDecrease, 24 * 60 * 60 * 1000);

// Auth routes
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        
        // Check if user exists
        const [existing] = await pool.execute(
            'SELECT id FROM users WHERE username = ? OR email = ?',
            [username, email]
        );
        
        if (existing.length > 0) {
            return res.status(400).json({ error: 'User already exists' });
        }
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Check if this is the first user (make super admin)
        const [users] = await pool.execute('SELECT COUNT(*) as count FROM users');
        const role = users[0].count === 0 ? 'super_admin' : 'user';
        
        // Create user
        const [result] = await pool.execute(
            'INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)',
            [username, email, hashedPassword, role]
        );
        
        res.status(201).json({ message: 'User created successfully' });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // Find user
        const [users] = await pool.execute(
            'SELECT * FROM users WHERE username = ?',
            [username]
        );
        
        if (users.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const user = users[0];
        
        // Check if banned
        if (user.is_banned) {
            return res.status(403).json({ error: 'Account is banned' });
        }
        
        // Verify password
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Create token
        const token = jwt.sign(
            { id: user.id, username: user.username, role: user.role },
            process.env.JWT_SECRET || 'your-secret-key',
            { expiresIn: '7d' }
        );
        
        // Remove password hash from response
        delete user.password_hash;
        
        res.json({ token, user });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// 在server.js中，修改posts表的SQL查询
app.get('/api/posts', async (req, res) => {
    try {
        const [posts] = await pool.execute(`
            SELECT p.*, u.username, u.vitality, u.role,
                   (SELECT COUNT(*) FROM likes WHERE post_id = p.id) as likes_count,
                   (SELECT COUNT(*) FROM usefuls WHERE post_id = p.id) as useful_count,
                   (SELECT COUNT(*) FROM replies WHERE post_id = p.id) as replies_count
            FROM posts p
            JOIN users u ON p.author_id = u.id
            ORDER BY p.created_at DESC
            LIMIT 50
        `);
        
        res.json(posts);
    } catch (error) {
        console.error('Error fetching posts:', error);
        console.error('Error details:', error.message);
        res.status(500).json({ 
            error: 'Internal server error',
            details: error.message 
        });
    }
});

app.post('/api/posts', authenticateToken, async (req, res) => {
    try {
        const { title, content } = req.body;
        const userId = req.user.id;
        
        console.log('Creating post:', { userId, title, content });
        
        // 检查用户是否可以发帖
        const [user] = await pool.execute(
            'SELECT can_post FROM users WHERE id = ?',
            [userId]
        );
        
        // 注意：这里要检查数组是否为空
        if (user.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        if (!user[0].can_post) {
            return res.status(403).json({ error: 'Posting is disabled for your account' });
        }
        
        // 创建帖子
        const [result] = await pool.execute(
            'INSERT INTO posts (author_id, title, content) VALUES (?, ?, ?)',
            [userId, title, content]
        );
        
        console.log('Post created with ID:', result.insertId);
        
        // 更新活力值
        await updateVitality(userId, 2, 'create_post', 'post', result.insertId);
        
        res.status(201).json({ 
            id: result.insertId, 
            message: 'Post created successfully' 
        });
    } catch (error) {
        console.error('Error creating post:', error);
        console.error('Error stack:', error.stack);
        res.status(500).json({ 
            error: 'Internal server error',
            details: error.message,
            stack: error.stack
        });
    }
});

app.delete('/api/posts/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        const postId = req.params.id;
        const adminId = req.user.id;
        
        // Get post author
        const [posts] = await pool.execute(
            'SELECT author_id FROM posts WHERE id = ?',
            [postId]
        );
        
        if (posts.length === 0) {
            return res.status(404).json({ error: 'Post not found' });
        }
        
        const authorId = posts[0].author_id;
        
        // Delete post
        await pool.execute('DELETE FROM posts WHERE id = ?', [postId]);
        
        // Send report to super admin if not super admin
        if (req.user.role !== 'super_admin') {
            const [superAdmins] = await pool.execute(
                "SELECT id FROM users WHERE role = 'super_admin'"
            );
            
            for (const admin of superAdmins) {
                await pool.execute(
                    'INSERT INTO messages (sender_id, receiver_id, content) VALUES (?, ?, ?)',
                    [adminId, admin.id, `Admin ${req.user.username} deleted post #${postId} from user ${authorId}`]
                );
            }
        }
        
        // Update vitality (-2 for post deletion)
        await updateVitality(authorId, -2, 'post_deleted');
        
        res.json({ message: 'Post deleted successfully' });
    } catch (error) {
        console.error('Error deleting post:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Likes routes
app.post('/api/posts/:id/like', authenticateToken, async (req, res) => {
    try {
        const postId = req.params.id;
        const userId = req.user.id;
        
        // Check if user can like
        const [user] = await pool.execute(
            'SELECT can_like FROM users WHERE id = ?',
            [userId]
        );
        
        if (!user[0].can_like) {
            return res.status(403).json({ error: 'Liking is disabled for your account' });
        }
        
        // Check if already liked
        const [existing] = await pool.execute(
            'SELECT id FROM likes WHERE author_id = ? AND post_id = ?',
            [userId, postId]
        );
        
        if (existing.length > 0) {
            // Unlike
            await pool.execute(
                'DELETE FROM likes WHERE author_id = ? AND post_id = ?',
                [userId, postId]
            );
            
            // Get post author for vitality update
            const [posts] = await pool.execute(
                'SELECT author_id FROM posts WHERE id = ?',
                [postId]
            );
            
            if (posts.length > 0) {
                await updateVitality(posts[0].author_id, -2, 'post_unliked');
            }
            
            res.json({ liked: false });
        } else {
            // Like
            await pool.execute(
                'INSERT INTO likes (author_id, post_id) VALUES (?, ?)',
                [userId, postId]
            );
            
            // Get post author for vitality update
            const [posts] = await pool.execute(
                'SELECT author_id FROM posts WHERE id = ?',
                [postId]
            );
            
            if (posts.length > 0) {
                await updateVitality(posts[0].author_id, 2, 'post_liked');
            }
            
            res.json({ liked: true });
        }
    } catch (error) {
        console.error('Error liking post:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Useful routes
app.post('/api/posts/:id/useful', authenticateToken, async (req, res) => {
    try {
        const postId = req.params.id;
        const userId = req.user.id;
        
        // Check if already marked useful
        const [existing] = await pool.execute(
            'SELECT id FROM usefuls WHERE author_id = ? AND post_id = ?',
            [userId, postId]
        );
        
        if (existing.length > 0) {
            // Remove useful mark
            await pool.execute(
                'DELETE FROM usefuls WHERE author_id = ? AND post_id = ?',
                [userId, postId]
            );
            
            // Get post author for vitality update
            const [posts] = await pool.execute(
                'SELECT author_id FROM posts WHERE id = ?',
                [postId]
            );
            
            if (posts.length > 0) {
                await updateVitality(posts[0].author_id, -5, 'post_useful_removed');
            }
            
            res.json({ useful: false });
        } else {
            // Mark useful
            await pool.execute(
                'INSERT INTO usefuls (author_id, post_id) VALUES (?, ?)',
                [userId, postId]
            );
            
            // Get post author for vitality update
            const [posts] = await pool.execute(
                'SELECT author_id FROM posts WHERE id = ?',
                [postId]
            );
            
            if (posts.length > 0) {
                await updateVitality(posts[0].author_id, 5, 'post_marked_useful');
            }
            
            res.json({ useful: true });
        }
    } catch (error) {
        console.error('Error marking post useful:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Replies routes
app.get('/api/posts/:id/replies', async (req, res) => {
    try {
        const postId = req.params.id;
        
        const [replies] = await pool.execute(`
            SELECT r.*, u.username, u.vitality, u.role,
                   (SELECT COUNT(*) FROM likes WHERE reply_id = r.id) as likes_count,
                   (SELECT COUNT(*) FROM usefuls WHERE reply_id = r.id) as useful_count
            FROM replies r
            JOIN users u ON r.author_id = u.id
            WHERE r.post_id = ?
            ORDER BY r.created_at ASC
        `, [postId]);
        
        res.json(replies);
    } catch (error) {
        console.error('Error fetching replies:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/posts/:id/replies', authenticateToken, async (req, res) => {
    try {
        const postId = req.params.id;
        const { content } = req.body;
        const userId = req.user.id;
        
        // Check if user can reply
        const [user] = await pool.execute(
            'SELECT can_post FROM users WHERE id = ?',
            [userId]
        );
        
        if (!user[0].can_post) {
            return res.status(403).json({ error: 'Posting is disabled for your account' });
        }
        
        // Create reply
        const [result] = await pool.execute(
            'INSERT INTO replies (post_id, author_id, content) VALUES (?, ?, ?)',
            [postId, userId, content]
        );
        
        // Update vitality (+1 for replying)
        await updateVitality(userId, 1, 'create_reply');
        
        res.status(201).json({ id: result.insertId, message: 'Reply created successfully' });
    } catch (error) {
        console.error('Error creating reply:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// User routes
app.get('/api/users/:id', authenticateToken, async (req, res) => {
    try {
        const userId = req.params.id;
        
        const [users] = await pool.execute(`
            SELECT id, username, email, bio, signature, vitality, role, created_at,
                   (SELECT COUNT(*) FROM posts WHERE author_id = ?) as post_count,
                   (SELECT COUNT(*) FROM replies WHERE author_id = ?) as reply_count,
                   (SELECT COUNT(*) FROM follows WHERE follower_id = ?) as following_count,
                   (SELECT COUNT(*) FROM follows WHERE following_id = ?) as followers_count,
                   (SELECT COUNT(*) FROM usefuls WHERE (post_id IN (SELECT id FROM posts WHERE author_id = ?) OR 
                                                       reply_id IN (SELECT id FROM replies WHERE author_id = ?))) as useful_count
            FROM users
            WHERE id = ?
        `, [userId, userId, userId, userId, userId, userId, userId]);
        
        if (users.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        res.json(users[0]);
    } catch (error) {
        console.error('Error fetching user:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.put('/api/users/:id', authenticateToken, async (req, res) => {
    try {
        const userId = req.params.id;
        const { bio, signature } = req.body;
        
        // Check if user is updating their own profile
        if (req.user.id != userId && req.user.role !== 'admin' && req.user.role !== 'super_admin') {
            return res.status(403).json({ error: 'Cannot update other user\'s profile' });
        }
        
        await pool.execute(
            'UPDATE users SET bio = ?, signature = ? WHERE id = ?',
            [bio, signature, userId]
        );
        
        res.json({ message: 'Profile updated successfully' });
    } catch (error) {
        console.error('Error updating user:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Follow routes
app.post('/api/users/:id/follow', authenticateToken, async (req, res) => {
    try {
        const followingId = req.params.id;
        const followerId = req.user.id;
        
        if (followerId == followingId) {
            return res.status(400).json({ error: 'Cannot follow yourself' });
        }
        
        // Check if already following
        const [existing] = await pool.execute(
            'SELECT id FROM follows WHERE follower_id = ? AND following_id = ?',
            [followerId, followingId]
        );
        
        if (existing.length > 0) {
            // Unfollow
            await pool.execute(
                'DELETE FROM follows WHERE follower_id = ? AND following_id = ?',
                [followerId, followingId]
            );
            
            await updateVitality(followingId, -5, 'unfollowed');
            res.json({ following: false });
        } else {
            // Follow
            await pool.execute(
                'INSERT INTO follows (follower_id, following_id) VALUES (?, ?)',
                [followerId, followingId]
            );
            
            await updateVitality(followingId, 5, 'followed');
            res.json({ following: true });
        }
    } catch (error) {
        console.error('Error following user:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Messages routes
app.get('/api/messages/conversations', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        
        const [conversations] = await pool.execute(`
            SELECT DISTINCT 
                CASE 
                    WHEN m.sender_id = ? THEN m.receiver_id 
                    ELSE m.sender_id 
                END as author_id,
                u.username,
                MAX(m.created_at) as last_message_time,
                (SELECT content FROM messages WHERE 
                    (sender_id = ? AND receiver_id = u.id) OR 
                    (sender_id = u.id AND receiver_id = ?)
                 ORDER BY created_at DESC LIMIT 1) as last_message
            FROM messages m
            JOIN users u ON (u.id = CASE 
                WHEN m.sender_id = ? THEN m.receiver_id 
                ELSE m.sender_id 
            END)
            WHERE m.sender_id = ? OR m.receiver_id = ?
            GROUP BY author_id, u.username
            ORDER BY last_message_time DESC
        `, [userId, userId, userId, userId, userId, userId]);
        
        res.json(conversations);
    } catch (error) {
        console.error('Error fetching conversations:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/messages/:userId', authenticateToken, async (req, res) => {
    try {
        const otherUserId = req.params.userId;
        const currentUserId = req.user.id;
        
        // Check if user can message
        const [user] = await pool.execute(
            'SELECT can_message FROM users WHERE id = ?',
            [currentUserId]
        );
        
        if (!user[0].can_message) {
            return res.status(403).json({ error: 'Messaging is disabled for your account' });
        }
        
        const [messages] = await pool.execute(`
            SELECT m.*, u.username as sender_name
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE (m.sender_id = ? AND m.receiver_id = ?)
               OR (m.sender_id = ? AND m.receiver_id = ?)
            ORDER BY m.created_at ASC
        `, [currentUserId, otherUserId, otherUserId, currentUserId]);
        
        // Mark messages as read
        await pool.execute(
            'UPDATE messages SET is_read = TRUE WHERE sender_id = ? AND receiver_id = ? AND is_read = FALSE',
            [otherUserId, currentUserId]
        );
        
        res.json(messages);
    } catch (error) {
        console.error('Error fetching messages:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/messages', authenticateToken, async (req, res) => {
    try {
        const { receiver_id, content } = req.body;
        const senderId = req.user.id;
        
        // Check if user can message
        const [user] = await pool.execute(
            'SELECT can_message FROM users WHERE id = ?',
            [senderId]
        );
        
        if (!user[0].can_message) {
            return res.status(403).json({ error: 'Messaging is disabled for your account' });
        }
        
        // Check if receiver exists
        const [receivers] = await pool.execute(
            'SELECT id FROM users WHERE id = ?',
            [receiver_id]
        );
        
        if (receivers.length === 0) {
            return res.status(404).json({ error: 'Receiver not found' });
        }
        
        // Send message
        const [result] = await pool.execute(
            'INSERT INTO messages (sender_id, receiver_id, content) VALUES (?, ?, ?)',
            [senderId, receiver_id, content]
        );
        
        res.status(201).json({ id: result.insertId, message: 'Message sent successfully' });
    } catch (error) {
        console.error('Error sending message:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Tickets routes
app.post('/api/tickets', authenticateToken, async (req, res) => {
    try {
        const { title, content } = req.body;
        const userId = req.user.id;
        
        const [result] = await pool.execute(
            'INSERT INTO tickets (author_id, title, content) VALUES (?, ?, ?)',
            [userId, title, content]
        );
        
        res.status(201).json({ id: result.insertId, message: 'Ticket created successfully' });
    } catch (error) {
        console.error('Error creating ticket:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get user's tickets
app.get('/api/tickets/user', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        console.log('Fetching tickets for user:', userId);
        
        const [tickets] = await pool.execute(
            'SELECT * FROM tickets WHERE author_id = ? ORDER BY created_at DESC',
            [userId]
        );
        
        console.log('Found tickets:', tickets.length);
        res.json(tickets);
    } catch (error) {
        console.error('Error fetching user tickets:', error);
        res.status(500).json({ 
            error: 'Internal server error',
            details: error.message 
        });
    }
});

// Get all tickets (admin only)
app.get('/api/tickets', authenticateToken, isAdmin, async (req, res) => {
    try {
        console.log('Fetching all tickets (admin)');
        
        const [tickets] = await pool.execute(`
            SELECT t.*, u.username 
            FROM tickets t 
            JOIN users u ON t.author_id = u.id 
            ORDER BY t.created_at DESC
        `);
        
        res.json(tickets);
    } catch (error) {
        console.error('Error fetching all tickets:', error);
        res.status(500).json({ 
            error: 'Internal server error',
            details: error.message 
        });
    }
});

// Update ticket status
app.put('/api/tickets/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        const ticketId = req.params.id;
        const { status } = req.body;
        
        console.log('Updating ticket:', ticketId, 'to status:', status);
        
        // Validate status
        const validStatuses = ['open', 'pending', 'closed', 'deleted', 'completed'];
        if (!validStatuses.includes(status)) {
            return res.status(400).json({ error: 'Invalid status' });
        }
        
        await pool.execute(
            'UPDATE tickets SET status = ? WHERE id = ?',
            [status, ticketId]
        );
        
        res.json({ message: 'Ticket status updated successfully' });
    } catch (error) {
        console.error('Error updating ticket:', error);
        res.status(500).json({ 
            error: 'Internal server error',
            details: error.message 
        });
    }
});

// Delete ticket
app.delete('/api/tickets/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        const ticketId = req.params.id;
        console.log('Deleting ticket:', ticketId);
        
        await pool.execute(
            'DELETE FROM tickets WHERE id = ?',
            [ticketId]
        );
        
        res.json({ message: 'Ticket deleted successfully' });
    } catch (error) {
        console.error('Error deleting ticket:', error);
        res.status(500).json({ 
            error: 'Internal server error',
            details: error.message 
        });
    }
});

// Admin routes
app.post('/api/admin/warn', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { author_id, reason } = req.body;
        const adminId = req.user.id;
        
        await pool.execute(
            'INSERT INTO warnings (author_id, admin_id, reason) VALUES (?, ?, ?)',
            [author_id, adminId, reason]
        );
        
        res.json({ message: 'Warning sent successfully' });
    } catch (error) {
        console.error('Error sending warning:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/admin/ban', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { author_id, reason, ban_type, duration_hours } = req.body;
        const adminId = req.user.id;
        
        let endTime = null;
        if (duration_hours) {
            endTime = new Date();
            endTime.setHours(endTime.getHours() + duration_hours);
        }
        
        await pool.execute(
            'INSERT INTO bans (author_id, admin_id, reason, ban_type, end_time) VALUES (?, ?, ?, ?, ?)',
            [author_id, adminId, reason, ban_type, endTime]
        );
        
        // Update user permissions based on ban type
        switch (ban_type) {
            case 'post':
                await pool.execute('UPDATE users SET can_post = FALSE WHERE id = ?', [author_id]);
                break;
            case 'like':
                await pool.execute('UPDATE users SET can_like = FALSE WHERE id = ?', [author_id]);
                break;
            case 'message':
                await pool.execute('UPDATE users SET can_message = FALSE WHERE id = ?', [author_id]);
                break;
            case 'account':
                await pool.execute('UPDATE users SET is_banned = TRUE WHERE id = ?', [author_id]);
                break;
        }
        
        // Send report to super admin if not super admin
        if (req.user.role !== 'super_admin') {
            const [superAdmins] = await pool.execute(
                "SELECT id FROM users WHERE role = 'super_admin'"
            );
            
            for (const admin of superAdmins) {
                await pool.execute(
                    'INSERT INTO messages (sender_id, receiver_id, content) VALUES (?, ?, ?)',
                    [adminId, admin.id, `Admin ${req.user.username} banned user ${author_id} for ${ban_type} (${reason})`]
                );
            }
        }
        
        res.json({ message: 'Ban applied successfully' });
    } catch (error) {
        console.error('Error applying ban:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/admin/promote', authenticateToken, isSuperAdmin, async (req, res) => {
    try {
        const { author_id } = req.body;
        
        await pool.execute(
            "UPDATE users SET role = 'admin' WHERE id = ?",
            [author_id]
        );
        
        res.json({ message: 'User promoted to admin' });
    } catch (error) {
        console.error('Error promoting user:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Start server
async function startServer() {
    await initDB();
    
    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
    });
}

startServer().catch(console.error);
