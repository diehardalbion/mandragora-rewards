const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:5500',
    credentials: true
}));
app.use(express.json());

// ===== HELPERS =====
function generateToken() {
    return crypto.randomBytes(32).toString('hex');
}

// ===== MIDDLEWARE =====
const adminAuth = (req, res, next) => {
    const token = req.headers['x-admin-token'];
    if (token !== process.env.ADMIN_API_TOKEN) {
        return res.status(403).json({ error: 'Acesso negado' });
    }
    next();
};

// ===== AUTH DISCORD OAUTH2 =====

// Passo 1: Redireciona usuario para o Discord
app.get('/api/auth/discord', (req, res) => {
    const clientId = process.env.DISCORD_CLIENT_ID;
    const redirectUri = encodeURIComponent(`${process.env.API_URL}/api/auth/discord/callback`);
    const scope = encodeURIComponent('identify guilds');
    const state = generateToken(); // protecao CSRF

    // Salva state temporario (em producao use Redis, aqui simplificado)
    // Por simplicidade, vamos validar o state na callback

    const discordUrl = `https://discord.com/oauth2/authorize?client_id=${clientId}&redirect_uri=${redirectUri}&response_type=code&scope=${scope}&state=${state}`;

    res.json({ url: discordUrl, state });
});

// Passo 2: Discord redireciona de volta com "code"
app.get('/api/auth/discord/callback', async (req, res) => {
    const code = req.query.code;

    if (!code) {
        return res.redirect(`${process.env.FRONTEND_URL}?error=no_code`);
    }

    try {
        // Troca o code por access_token
        const tokenResponse = await fetch('https://discord.com/api/oauth2/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                client_id: process.env.DISCORD_CLIENT_ID,
                client_secret: process.env.DISCORD_CLIENT_SECRET,
                grant_type: 'authorization_code',
                code: code,
                redirect_uri: `${process.env.API_URL}/api/auth/discord/callback`,
            })
        });

        const tokenData = await tokenResponse.json();

        if (!tokenData.access_token) {
            return res.redirect(`${process.env.FRONTEND_URL}?error=token_failed`);
        }

        // Pega dados do usuario
        const userResponse = await fetch('https://discord.com/api/users/@me', {
            headers: { Authorization: `Bearer ${tokenData.access_token}` }
        });

        const discordUser = await userResponse.json();

        // Salva/atualiza usuario no banco
        await pool.query(`
            INSERT INTO users (discord_id, discord_name, avatar_url, points, total_time_minutes)
            VALUES ($1, $2, $3, 0, 0)
            ON CONFLICT (discord_id) 
            DO UPDATE SET discord_name = $2, avatar_url = $3, updated_at = NOW()
        `, [
            discordUser.id,
            discordUser.username,
            discordUser.avatar 
                ? `https://cdn.discordapp.com/avatars/${discordUser.id}/${discordUser.avatar}.png`
                : null
        ]);

        // Gera JWT simples (token de sessao)
        const sessionToken = generateToken();

        // Salva sessao (em producao use Redis ou tabela sessions)
        await pool.query(`
            INSERT INTO user_sessions (token, discord_id, expires_at)
            VALUES ($1, $2, NOW() + INTERVAL '7 days')
            ON CONFLICT (token) DO UPDATE SET expires_at = NOW() + INTERVAL '7 days'
        `, [sessionToken, discordUser.id]);

        // Redireciona de volta pro site com o token
        res.redirect(`${process.env.FRONTEND_URL}?token=${sessionToken}&user=${encodeURIComponent(discordUser.username)}&id=${discordUser.id}`);

    } catch (err) {
        console.error('Erro no callback Discord:', err);
        res.redirect(`${process.env.FRONTEND_URL}?error=auth_failed`);
    }
});

// Verifica sessao
app.get('/api/auth/me', async (req, res) => {
    const token = req.headers['x-session-token'];
    if (!token) return res.status(401).json({ error: 'Nao autenticado' });

    try {
        const { rows } = await pool.query(`
            SELECT u.* FROM users u
            JOIN user_sessions s ON u.discord_id = s.discord_id
            WHERE s.token = $1 AND s.expires_at > NOW()
        `, [token]);

        if (rows.length === 0) return res.status(401).json({ error: 'Sessao invalida' });

        res.json(rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Logout
app.post('/api/auth/logout', async (req, res) => {
    const token = req.headers['x-session-token'];
    if (token) {
        await pool.query('DELETE FROM user_sessions WHERE token = $1', [token]);
    }
    res.json({ success: true });
});

// ===== ROTAS PUBLICAS =====

// Ranking
app.get('/api/leaderboard', async (req, res) => {
    try {
        const { rows } = await pool.query(
            'SELECT discord_name, points, total_time_minutes, avatar_url FROM users ORDER BY points DESC LIMIT 50'
        );
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Recompensas
app.get('/api/rewards', async (req, res) => {
    try {
        const { rows } = await pool.query(
            'SELECT id, name, description, points_cost, stock, icon, image_url FROM rewards WHERE is_active = TRUE ORDER BY points_cost ASC'
        );
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Stats de um usuario (por discord_id)
app.get('/api/user/:discordId', async (req, res) => {
    try {
        const { rows } = await pool.query(
            'SELECT discord_name, points, total_time_minutes, avatar_url FROM users WHERE discord_id = $1',
            [req.params.discordId]
        );
        if (rows.length === 0) return res.status(404).json({ error: 'Usuario nao encontrado' });

        const redRows = await pool.query(
            'SELECT COUNT(*) as count FROM redemptions WHERE discord_id = $1',
            [req.params.discordId]
        );

        res.json({
            ...rows[0],
            redemptions: parseInt(redRows.rows[0].count)
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Resgatar recompensa (precisa estar logado)
app.post('/api/redeem', async (req, res) => {
    const token = req.headers['x-session-token'];
    const { reward_id } = req.body;

    if (!token) return res.status(401).json({ error: 'Nao autenticado' });

    try {
        // Verifica sessao
        const sess = await pool.query(`
            SELECT discord_id FROM user_sessions 
            WHERE token = $1 AND expires_at > NOW()
        `, [token]);

        if (sess.rows.length === 0) return res.status(401).json({ error: 'Sessao invalida' });

        const discord_id = sess.rows[0].discord_id;

        // Busca usuario e recompensa
        const user = await pool.query('SELECT * FROM users WHERE discord_id = $1', [discord_id]);
        const reward = await pool.query('SELECT * FROM rewards WHERE id = $1 AND is_active = TRUE', [reward_id]);

        if (user.rows.length === 0) return res.status(404).json({ error: 'Usuario nao encontrado' });
        if (reward.rows.length === 0) return res.status(404).json({ error: 'Recompensa nao encontrada' });

        const u = user.rows[0];
        const r = reward.rows[0];

        if (u.points < r.points_cost) {
            return res.status(400).json({ error: 'Pontos insuficientes' });
        }

        if (r.stock === 0) {
            return res.status(400).json({ error: 'Recompensa esgotada' });
        }

        // Deduz pontos
        await pool.query('UPDATE users SET points = points - $2 WHERE discord_id = $1', [discord_id, r.points_cost]);

        // Diminui estoque
        if (r.stock > 0) {
            await pool.query('UPDATE rewards SET stock = stock - 1 WHERE id = $1', [reward_id]);
        }

        // Cria resgate
        const redId = await pool.query(
            'INSERT INTO redemptions (discord_id, reward_id, status) VALUES ($1, $2, $3) RETURNING id',
            [discord_id, reward_id, 'pending']
        );

        res.json({ 
            success: true, 
            redemption_id: redId.rows[0].id,
            remaining_points: u.points - r.points_cost
        });

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ===== ROTAS ADMIN (protegidas) =====

app.get('/api/admin/stats', adminAuth, async (req, res) => {
    try {
        const users = await pool.query('SELECT COUNT(*) as count FROM users');
        const points = await pool.query('SELECT COALESCE(SUM(points), 0) as total FROM users');
        const pending = await pool.query("SELECT COUNT(*) as count FROM redemptions WHERE status = 'pending'");
        const delivered = await pool.query("SELECT COUNT(*) as count FROM redemptions WHERE status = 'delivered'");

        res.json({
            total_users: parseInt(users.rows[0].count),
            total_points: parseFloat(points.rows[0].total),
            pending: parseInt(pending.rows[0].count),
            delivered: parseInt(delivered.rows[0].count)
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/admin/pending', adminAuth, async (req, res) => {
    try {
        const { rows } = await pool.query(`
            SELECT r.id, u.discord_name, u.discord_id, rw.name as reward_name, rw.points_cost, r.redeemed_at
            FROM redemptions r
            JOIN users u ON r.discord_id = u.discord_id
            JOIN rewards rw ON r.reward_id = rw.id
            WHERE r.status = 'pending' ORDER BY r.redeemed_at ASC
        `);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/admin/history', adminAuth, async (req, res) => {
    try {
        const { rows } = await pool.query(`
            SELECT r.id, u.discord_name, rw.name as reward_name, r.status, r.redeemed_at
            FROM redemptions r
            JOIN users u ON r.discord_id = u.discord_id
            JOIN rewards rw ON r.reward_id = rw.id
            ORDER BY r.redeemed_at DESC LIMIT 100
        `);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/admin/deliver/:id', adminAuth, async (req, res) => {
    try {
        await pool.query(
            "UPDATE redemptions SET status = 'delivered', delivered_at = NOW() WHERE id = $1",
            [req.params.id]
        );
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/admin/cancel/:id', adminAuth, async (req, res) => {
    try {
        // Primeiro devolve os pontos
        const red = await pool.query('SELECT * FROM redemptions WHERE id = $1', [req.params.id]);
        if (red.rows.length > 0) {
            const r = red.rows[0];
            const reward = await pool.query('SELECT points_cost FROM rewards WHERE id = $1', [r.reward_id]);
            if (reward.rows.length > 0) {
                await pool.query('UPDATE users SET points = points + $2 WHERE discord_id = $1', 
                    [r.discord_id, reward.rows[0].points_cost]);
            }
        }

        await pool.query(
            "UPDATE redemptions SET status = 'cancelled' WHERE id = $1",
            [req.params.id]
        );
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/admin/rewards', adminAuth, async (req, res) => {
    try {
        const { rows } = await pool.query('SELECT * FROM rewards ORDER BY id ASC');
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/admin/rewards', adminAuth, async (req, res) => {
    const { name, description, points_cost, stock, icon, image_url } = req.body;
    try {
        const { rows } = await pool.query(
            'INSERT INTO rewards (name, description, points_cost, stock, icon, image_url) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
            [name, description || name, points_cost, stock || -1, icon || '🎁', image_url || null]
        );
        res.json(rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/admin/users', adminAuth, async (req, res) => {
    try {
        const { rows } = await pool.query(
            'SELECT discord_name, points, total_time_minutes FROM users ORDER BY points DESC'
        );
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 API rodando na porta ${PORT}`);
});
