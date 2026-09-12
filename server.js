const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');
const cors = require('cors');

const app = express();
// Tự động nhận cổng do môi trường cấp (hoặc mặc định chạy cổng 3000 trên máy)
const PORT = process.env.PORT || 3000;

// ==========================================
// 1. CẤU HÌNH MIDDLEWARE
// ==========================================
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// ==========================================
// 2. KHỞI TẠO CƠ SỞ DỮ LIỆU SQLITE
// ==========================================
const db = new sqlite3.Database('./database.sqlite', (err) => {
  if (err) {
    console.error('Lỗi kết nối CSDL:', err.message);
  } else {
    console.log('-> Kết nối CSDL SQLite thành công!');
  }
});

// Tạo các bảng cơ sở dữ liệu
db.serialize(() => {
  // Bảng tài khoản người dùng
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT DEFAULT 'Thành viên',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `, () => {
    // Tự động gán quyền Chủ quân đoàn cho email quản trị viên
    db.run(
      "UPDATE users SET role = 'Chủ quân đoàn' WHERE email = 'luonghaonhat87@gmail.com'",
      function (err) {
        if (!err && this.changes > 0) {
          console.log('-> Đã cấp quyền Chủ quân đoàn cho: luonghaonhat87@gmail.com');
        }
      }
    );
  });

  // Bảng lưu kết quả chia team giải đấu (1 người chỉ thuộc 1 team)
  db.run(`
    CREATE TABLE IF NOT EXISTS tournament_teams (
      user_id INTEGER PRIMARY KEY,
      team_number INTEGER NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `);
});

// ==========================================
// 3. CÁC ĐỊNH TUYẾN GIAO DIỆN (ROUTES)
// ==========================================
// Định tuyến trang chủ mặc định tránh lỗi "Cannot GET /"
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ==========================================
// 4. HỆ THỐNG API XÁC THỰC TÀI KHOẢN
// ==========================================

// API Đăng ký: POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ success: false, message: 'Vui lòng điền đủ thông tin!' });
  }

  const cleanEmail = email.trim().toLowerCase();

  db.get('SELECT id FROM users WHERE email = ?', [cleanEmail], async (err, row) => {
    if (err) return res.status(500).json({ success: false, message: 'Lỗi hệ thống.' });
    if (row) return res.status(409).json({ success: false, message: 'Email này đã tồn tại!' });

    try {
      const hashedPassword = await bcrypt.hash(password, 10);
      const role = (cleanEmail === 'luonghaonhat87@gmail.com') ? 'Chủ quân đoàn' : 'Thành viên';

      db.run(
        'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
        [username.trim(), cleanEmail, hashedPassword, role],
        function (insertErr) {
          if (insertErr) {
            return res.status(500).json({ success: false, message: 'Lỗi khi lưu tài khoản.' });
          }
          return res.status(201).json({
            success: true,
            message: `Đăng ký thành công với chức vụ: ${role}!`
          });
        }
      );
    } catch (hashErr) {
      return res.status(500).json({ success: false, message: 'Lỗi mã hóa mật khẩu.' });
    }
  });
});

// API Đăng nhập: POST /api/auth/login
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ success: false, message: 'Vui lòng nhập đủ email và mật khẩu!' });
  }

  const cleanEmail = email.trim().toLowerCase();

  db.get('SELECT * FROM users WHERE email = ?', [cleanEmail], async (err, user) => {
    if (err) return res.status(500).json({ success: false, message: 'Lỗi hệ thống.' });
    if (!user) return res.status(401).json({ success: false, message: 'Email hoặc mật khẩu không chính xác!' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ success: false, message: 'Email hoặc mật khẩu không chính xác!' });

    return res.json({
      success: true,
      message: 'Đăng nhập thành công!',
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role
      }
    });
  });
});

// API Đổi mật khẩu: POST /api/auth/change-password
app.post('/api/auth/change-password', async (req, res) => {
  const { userId, oldPassword, newPassword } = req.body;

  if (!userId || !oldPassword || !newPassword) {
    return res.status(400).json({ success: false, message: 'Vui lòng điền đủ thông tin!' });
  }

  if (newPassword.length < 6) {
    return res.status(400).json({ success: false, message: 'Mật khẩu mới phải có ít nhất 6 ký tự!' });
  }

  db.get('SELECT * FROM users WHERE id = ?', [userId], async (err, user) => {
    if (err || !user) {
      return res.status(404).json({ success: false, message: 'Người dùng không tồn tại.' });
    }

    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ success: false, message: 'Mật khẩu cũ không chính xác!' });
    }

    const hashedNewPass = await bcrypt.hash(newPassword, 10);
    db.run('UPDATE users SET password = ? WHERE id = ?', [hashedNewPass, userId], (upErr) => {
      if (upErr) return res.status(500).json({ success: false, message: 'Lỗi khi đổi mật khẩu.' });
      return res.json({ success: true, message: 'Đổi mật khẩu thành công!' });
    });
  });
});

// ==========================================
// 5. HỆ THỐNG API QUẢN LÝ THÀNH VIÊN
// ==========================================

// Lấy toàn bộ danh sách thành viên: GET /api/members
app.get('/api/members', (req, res) => {
  const query = `
    SELECT id, username, email, role, created_at 
    FROM users 
    ORDER BY 
      CASE role
        WHEN 'Chủ quân đoàn' THEN 1
        WHEN 'Kỳ cựu' THEN 2
        ELSE 3
      END,
      id ASC
  `;

  db.all(query, [], (err, rows) => {
    if (err) {
      console.error('Lỗi nạp danh sách:', err.message);
      return res.status(500).json({ success: false, message: 'Lỗi máy chủ.' });
    }
    return res.json({ success: true, members: rows });
  });
});

// Phân quyền thành viên: PUT /api/members/role (Chỉ Chủ quân đoàn)
app.put('/api/members/role', (req, res) => {
  const { adminId, targetUserId, newRole } = req.body;

  const validRoles = ['Chủ quân đoàn', 'Kỳ cựu', 'Thành viên'];
  if (!validRoles.includes(newRole)) {
    return res.status(400).json({ success: false, message: 'Chức vụ không hợp lệ!' });
  }

  db.get('SELECT role FROM users WHERE id = ?', [adminId], (err, adminUser) => {
    if (err || !adminUser) {
      return res.status(500).json({ success: false, message: 'Lỗi xác thực quyền hạn.' });
    }

    if (adminUser.role !== 'Chủ quân đoàn') {
      return res.status(403).json({ success: false, message: 'Bạn không có quyền thay đổi chức vụ!' });
    }

    db.run(
      'UPDATE users SET role = ? WHERE id = ?',
      [newRole, targetUserId],
      function (updateErr) {
        if (updateErr) {
          return res.status(500).json({ success: false, message: 'Cập nhật chức vụ thất bại.' });
        }
        return res.json({ success: true, message: 'Cập nhật chức vụ thành công!' });
      }
    );
  });
});

// Xóa thành viên: DELETE /api/members/:targetUserId (Chỉ Chủ quân đoàn)
app.delete('/api/members/:targetUserId', (req, res) => {
  const targetUserId = parseInt(req.params.targetUserId, 10);
  const { adminId } = req.body;

  if (!adminId) {
    return res.status(400).json({ success: false, message: 'Thiếu thông tin xác thực quản trị viên!' });
  }

  if (parseInt(adminId, 10) === targetUserId) {
    return res.status(400).json({ success: false, message: 'Không thể tự xóa tài khoản của chính mình!' });
  }

  db.get('SELECT role FROM users WHERE id = ?', [adminId], (err, adminUser) => {
    if (err || !adminUser) {
      return res.status(500).json({ success: false, message: 'Lỗi xác thực quyền hạn.' });
    }

    if (adminUser.role !== 'Chủ quân đoàn') {
      return res.status(403).json({ success: false, message: 'Chỉ Chủ quân đoàn mới có quyền xóa thành viên!' });
    }

    // Xóa khỏi danh sách giải đấu trước nếu có
    db.run('DELETE FROM tournament_teams WHERE user_id = ?', [targetUserId], (teamDelErr) => {
      if (teamDelErr) {
        return res.status(500).json({ success: false, message: 'Lỗi khi xóa dữ liệu giải đấu.' });
      }

      // Xóa người dùng khỏi bảng users
      db.run('DELETE FROM users WHERE id = ?', [targetUserId], function (delErr) {
        if (delErr) {
          return res.status(500).json({ success: false, message: 'Lỗi khi xóa tài khoản khỏi CSDL.' });
        }
        return res.json({ success: true, message: 'Đã xóa vĩnh viễn thành viên khỏi quân đoàn!' });
      });
    });
  });
});

// ==========================================
// 6. HỆ THỐNG API GIẢI ĐẤU & VÒNG QUAY (12 TEAMS)
// ==========================================

// Lấy danh sách các team còn chỗ (< 4 người): GET /api/event/available-teams
app.get('/api/event/available-teams', (req, res) => {
  const query = `
    SELECT team_number, COUNT(*) as member_count
    FROM tournament_teams
    GROUP BY team_number
  `;

  db.all(query, [], (err, rows) => {
    if (err) return res.status(500).json({ success: false, message: 'Lỗi truy vấn.' });

    const counts = {};
    for (let i = 1; i <= 12; i++) counts[i] = 0;
    rows.forEach(r => { counts[r.team_number] = r.member_count; });

    const availableTeams = [];
    for (let i = 1; i <= 12; i++) {
      if (counts[i] < 4) {
        availableTeams.push(i);
      }
    }

    return res.json({ success: true, availableTeams, teamCounts: counts });
  });
});

// Thực hiện Quay Team: POST /api/event/spin (Server bốc thăm ngẫu nhiên)
app.post('/api/event/spin', (req, res) => {
  const { userId } = req.body;

  if (!userId) {
    return res.status(400).json({ success: false, message: 'Thiếu thông tin người dùng!' });
  }

  // Bước 1: Kiểm tra xem thành viên này đã quay trước đó chưa
  db.get('SELECT team_number FROM tournament_teams WHERE user_id = ?', [userId], (err, userRow) => {
    if (err) return res.status(500).json({ success: false, message: 'Lỗi kiểm tra người dùng.' });
    if (userRow) {
      return res.status(400).json({
        success: false,
        alreadySpun: true,
        teamNumber: userRow.team_number,
        message: `Bạn đã thuộc Team ${userRow.team_number} rồi, không thể quay lại!`
      });
    }

    // Bước 2: Lấy số lượng người của từng team hiện tại
    const query = `
      SELECT team_number, COUNT(*) as count 
      FROM tournament_teams 
      GROUP BY team_number
    `;
    db.all(query, [], (cntErr, rows) => {
      if (cntErr) return res.status(500).json({ success: false, message: 'Lỗi kiểm tra đội hình.' });

      const counts = {};
      for (let i = 1; i <= 12; i++) counts[i] = 0;
      rows.forEach(r => { counts[r.team_number] = r.count; });

      // Lọc ra danh sách các team còn nhận người (< 4 thành viên)
      const availableTeams = [];
      for (let i = 1; i <= 12; i++) {
        if (counts[i] < 4) {
          availableTeams.push(i);
        }
      }

      if (availableTeams.length === 0) {
        return res.status(400).json({ 
          success: false, 
          message: 'Tất cả 12 Team đã đủ 4 người! Giải đấu đã kín chỗ.' 
        });
      }

      // Bước 3: Server tự động bốc ngẫu nhiên 1 team hợp lệ
      const chosenTeam = availableTeams[Math.floor(Math.random() * availableTeams.length)];

      // Bước 4: Lưu kết quả vào CSDL
      db.run(
        'INSERT INTO tournament_teams (user_id, team_number) VALUES (?, ?)',
        [userId, chosenTeam],
        function (insErr) {
          if (insErr) {
            return res.status(500).json({ success: false, message: 'Lỗi ghi nhận kết quả quay.' });
          }
          return res.json({ 
            success: true, 
            teamNumber: chosenTeam,
            message: `Chúc mừng bạn đã gia nhập Team ${chosenTeam}!`
          });
        }
      );
    });
  });
});

// Lấy danh sách thành viên thuộc cùng 1 team: GET /api/event/team/:teamNumber
app.get('/api/event/team/:teamNumber', (req, res) => {
  const teamNumber = parseInt(req.params.teamNumber, 10);
  const query = `
    SELECT u.username, u.role, t.created_at
    FROM tournament_teams t
    JOIN users u ON t.user_id = u.id
    WHERE t.team_number = ?
    ORDER BY t.created_at ASC
  `;

  db.all(query, [teamNumber], (err, rows) => {
    if (err) return res.status(500).json({ success: false, message: 'Lỗi nạp danh sách đội.' });
    return res.json({ success: true, members: rows });
  });
});

// Kiểm tra trạng thái quay của người dùng: GET /api/event/user-status/:userId
app.get('/api/event/user-status/:userId', (req, res) => {
  const userId = parseInt(req.params.userId, 10);
  db.get('SELECT team_number FROM tournament_teams WHERE user_id = ?', [userId], (err, row) => {
    if (err) return res.status(500).json({ success: false, message: 'Lỗi kiểm tra trạng thái.' });
    return res.json({ success: true, hasSpun: !!row, teamNumber: row ? row.team_number : null });
  });
});

// ==========================================
// 7. KHỞI CHẠY MÁY CHỦ
// ==========================================
app.listen(PORT, '0.0.0.0', () => {
  console.log(`==================================================`);
  console.log(` Máy chủ đang chạy tại: http://localhost:${PORT}`);
  console.log(` Đăng nhập: /login.html`);
  console.log(` Đăng ký:   /register.html`);
  console.log(` Trang chủ: /index.html`);
  console.log(` Vòng quay: /wheel.html`);
  console.log(`==================================================`);
});