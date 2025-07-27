require('dotenv').config();
const express = require('express');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const Sequelize = require('sequelize');
const bcrypt = require('bcryptjs');
const path = require('path');
const { Op } = require('sequelize');
const { Parser } = require('json2csv');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
// Gmail transporter using environment variables
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_PASS
  }
});
// Define rate limiters before using them in routes
const forgotLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  message: 'Too many requests from this IP, please try again after 15 minutes.'
});
const codeLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many attempts, please try again after 15 minutes.'
});
const resetLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many attempts, please try again after 15 minutes.'
});

// DB setup
const sequelize = new Sequelize(
  process.env.DB_NAME,
  process.env.DB_USER,
  process.env.DB_PASSWORD,
  {
    host: process.env.DB_HOST,
    dialect: 'postgres',
    logging: false
  }
);

// User model
const User = sequelize.define('User', {
  firstName: { type: Sequelize.STRING, allowNull: false },
  lastName: { type: Sequelize.STRING, allowNull: false },
  email: { type: Sequelize.STRING, allowNull: false, unique: true },
  password: { type: Sequelize.STRING, allowNull: false },
  role: { type: Sequelize.ENUM('teacher', 'headmaster', 'admin'), allowNull: false, defaultValue: 'teacher' },
  periodsPerWeek: { type: Sequelize.INTEGER, allowNull: false, defaultValue: 0 },
  resetPasswordCode: { type: Sequelize.STRING },
  resetPasswordExpires: { type: Sequelize.DATE }
});

// TeachingRecord model
const TeachingRecord = sequelize.define('TeachingRecord', {
  date: { type: Sequelize.DATEONLY, allowNull: false },
  class: { type: Sequelize.STRING, allowNull: false },
  subject: { type: Sequelize.STRING, allowNull: false },
  period: { type: Sequelize.STRING, allowNull: false },
  topic: { type: Sequelize.STRING, allowNull: false },
  subtopic: { type: Sequelize.STRING },
  teacherWork: { type: Sequelize.TEXT, allowNull: false },
  studentWork: { type: Sequelize.TEXT, allowNull: false },
  remarks: { type: Sequelize.TEXT },
  status: { type: Sequelize.ENUM('draft', 'submitted', 'reviewed', 'rejected'), defaultValue: 'draft' },
  feedback: { type: Sequelize.TEXT },
  rating: { type: Sequelize.INTEGER, validate: { min: 1, max: 5 } },
  userId: { type: Sequelize.INTEGER, allowNull: false }
});

// Setup association for join
TeachingRecord.belongsTo(User, { foreignKey: 'userId' });

const app = express();
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
// Use persistent session store with connect-pg-simple
app.use(session({
  secret: 'your_secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 60 * 60 * 1000 } // 1 hour
}));

// Middleware to expose user to views
app.use((req, res, next) => {
  res.locals.user = req.session.user;
  next();
});

// Middleware to handle flash messages
const flashMessages = (req, res, next) => {
  res.locals.success = req.session.success;
  res.locals.error = req.session.error;
  delete req.session.success;
  delete req.session.error;
  next();
};
app.use(flashMessages);

// Role-based middleware
function isTeacher(req, res, next) {
  if (req.session.user && req.session.user.role === 'teacher') return next();
  res.redirect('/dashboard');
}
function isHeadmaster(req, res, next) {
  if (req.session.user && req.session.user.role === 'headmaster') return next();
  res.redirect('/dashboard');
}
function isAdmin(req, res, next) {
  if (req.session.user && req.session.user.role === 'admin') return next();
  res.redirect('/dashboard');
}

// Home
app.get('/', (req, res) => {
  res.render('index');
});

// Register
app.get('/register', (req, res) => {
  res.render('register', { error: null });
});
app.post('/register', async (req, res) => {
  const { firstName, lastName, email, password, password2 } = req.body;
  if (!firstName || !lastName || !email || !password || !password2) {
    return res.render('register', { error: 'All fields are required.' });
  }
  if (password !== password2) {
    return res.render('register', { error: 'Passwords do not match.' });
  }
  const existing = await User.findOne({ where: { email } });
  if (existing) {
    return res.render('register', { error: 'Email already registered.' });
  }
  const hash = await bcrypt.hash(password, 10);
  await User.create({
    firstName,
    lastName,
    email,
    password: hash,
    role: 'teacher' // Always assign teacher role
  });
  return res.redirect('/login');
});

// Login
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ where: { email } });
  if (!user) return res.render('login', { error: 'Invalid credentials.' });
  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.render('login', { error: 'Invalid credentials.' });
  req.session.user = { id: user.id, firstName: user.firstName, lastName: user.lastName, email: user.email, role: user.role };
  res.redirect('/dashboard');
});

// Dashboard
app.get('/dashboard', async (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  if (req.session.user.role === 'admin') return res.redirect('/admin');
  if (req.session.user.role === 'headmaster') return res.redirect('/headmaster');
  // Teacher dashboard: show weekly activity
  let weekRecords = [];
  if (req.session.user.role === 'teacher') {
    const weekStart = new Date();
    weekStart.setDate(weekStart.getDate() - weekStart.getDay());
    const weekEnd = new Date(weekStart);
    weekEnd.setDate(weekStart.getDate() + 6);
    weekRecords = await TeachingRecord.findAll({
      where: {
        userId: req.session.user.id,
        date: { [Op.between]: [weekStart, weekEnd] }
      },
      order: [['date', 'ASC']]
    });
  }
  res.render('dashboard', { user: req.session.user, weekRecords });
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

// Profile view/edit
app.get('/profile', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  res.render('profile', { user: req.session.user });
});
app.post('/profile', async (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  const { firstName, lastName, email } = req.body;
  if (!firstName || !lastName || !email) {
    req.session.error = 'All fields are required.';
    return res.redirect('/profile');
  }
  await User.update({ firstName, lastName, email }, { where: { id: req.session.user.id } });
  req.session.user.firstName = firstName;
  req.session.user.lastName = lastName;
  req.session.user.email = email;
  req.session.success = 'Profile updated successfully!';
  res.redirect('/profile');
});
// Password change
app.get('/profile/password', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  res.render('profile_password');
});
app.post('/profile/password', async (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  const { oldPassword, newPassword, newPassword2 } = req.body;
  if (!oldPassword || !newPassword || !newPassword2) {
    req.session.error = 'All fields are required.';
    return res.redirect('/profile/password');
  }
  if (newPassword !== newPassword2) {
    req.session.error = 'New passwords do not match.';
    return res.redirect('/profile/password');
  }
  const user = await User.findByPk(req.session.user.id);
  const match = await bcrypt.compare(oldPassword, user.password);
  if (!match) {
    req.session.error = 'Old password is incorrect.';
    return res.redirect('/profile/password');
  }
  const hash = await bcrypt.hash(newPassword, 10);
  await User.update({ password: hash }, { where: { id: req.session.user.id } });
  req.session.success = 'Password changed successfully!';
  res.redirect('/profile/password');
});

// List records for logged-in teacher
app.get('/records', async (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  let records;
  if (req.session.user.role === 'teacher') {
    records = await TeachingRecord.findAll({ where: { userId: req.session.user.id }, order: [['date', 'DESC']] });
  } else {
    records = await TeachingRecord.findAll({ order: [['date', 'DESC']] });
  }
  res.render('records', { records });
});

// Show form to create new record
app.get('/records/new', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  res.render('record_new', { error: null });
});

// Handle new record submission
app.post('/records/new', async (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  const { date, class: className, subject, period, topic, subtopic, teacherWork, studentWork, remarks } = req.body;
  if (!date || !className || !subject || !period || !topic || !teacherWork || !studentWork) {
    return res.render('record_new', { error: 'All required fields must be filled.' });
  }
  await TeachingRecord.create({
    date, class: className, subject, period, topic, subtopic, teacherWork, studentWork, remarks, userId: req.session.user.id
  });
  res.redirect('/records');
});

// View a single record
app.get('/records/:id', async (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  const record = await TeachingRecord.findOne({ where: { id: req.params.id, userId: req.session.user.id } });
  if (!record) return res.redirect('/records');
  res.render('record_view', { record });
});

// Edit a record (form) - only if teacher owns and status is draft
app.get('/records/:id/edit', async (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  const record = await TeachingRecord.findOne({ where: { id: req.params.id, userId: req.session.user.id } });
  if (!record || record.status !== 'draft') return res.redirect('/records');
  res.render('record_edit', { record, error: null });
});

// Handle edit submission - only if teacher owns and status is draft
app.post('/records/:id/edit', async (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  const record = await TeachingRecord.findOne({ where: { id: req.params.id, userId: req.session.user.id } });
  if (!record || record.status !== 'draft') return res.redirect('/records');
  const { date, class: className, subject, period, topic, subtopic, teacherWork, studentWork, remarks } = req.body;
  if (!date || !className || !subject || !period || !topic || !teacherWork || !studentWork) {
    return res.render('record_edit', { record, error: 'All required fields must be filled.' });
  }
  await TeachingRecord.update({
    date, class: className, subject, period, topic, subtopic, teacherWork, studentWork, remarks
  }, { where: { id: req.params.id, userId: req.session.user.id } });
  res.redirect('/records/' + req.params.id);
});

// Delete a record - only if teacher owns and status is draft
app.post('/records/:id/delete', async (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  const record = await TeachingRecord.findOne({ where: { id: req.params.id, userId: req.session.user.id } });
  if (!record || record.status !== 'draft') return res.redirect('/records');
  await TeachingRecord.destroy({ where: { id: req.params.id, userId: req.session.user.id } });
  res.redirect('/records');
});

// Teacher submit record (change status to submitted) - only if teacher owns and status is draft
app.post('/records/:id/submit', async (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  const record = await TeachingRecord.findOne({ where: { id: req.params.id, userId: req.session.user.id } });
  if (!record || record.status !== 'draft') return res.redirect('/records');
  await TeachingRecord.update({ status: 'submitted' }, { where: { id: req.params.id, userId: req.session.user.id } });
  res.redirect('/records/' + req.params.id);
});

// Change status (draft <-> submitted)
app.post('/records/:id/status', async (req, res) => {
  if (!req.session.user || (req.session.user.role !== 'admin' && req.session.user.role !== 'headmaster')) return res.redirect('/dashboard');
  const record = await TeachingRecord.findByPk(req.params.id);
  if (!record) return res.redirect('/records');
  let newStatus = record.status === 'draft' ? 'submitted' : record.status === 'submitted' ? 'reviewed' : 'draft';
  await TeachingRecord.update({ status: newStatus }, { where: { id: req.params.id } });
  res.redirect('/records/' + req.params.id);
});

// Admin panel: list users, change role, delete user, set periodsPerWeek
app.get('/admin', isAdmin, async (req, res) => {
  const users = await User.findAll({ order: [['role', 'ASC'], ['lastName', 'ASC']] });
  // Compute periods attended and latest feedback for each teacher
  const teacherPeriods = {};
  for (const user of users.filter(u => u.role === 'teacher')) {
    // Count submitted records
    const submitted = await TeachingRecord.count({ where: { userId: user.id, status: 'submitted' } });
    // Get latest feedback from headmaster
    const latest = await TeachingRecord.findOne({
      where: { userId: user.id, feedback: { [Op.ne]: null } },
      order: [['updatedAt', 'DESC']]
    });
    teacherPeriods[user.id] = {
      submitted,
      feedback: latest ? latest.feedback : null
    };
  }
  res.render('admin_panel', { users, teacherPeriods });
});
app.post('/admin/user/:id/role', isAdmin, async (req, res) => {
  const { role } = req.body;
  await User.update({ role }, { where: { id: req.params.id } });
  res.redirect('/admin');
});
app.post('/admin/user/:id/periods', isAdmin, async (req, res) => {
  const { periodsPerWeek } = req.body;
  await User.update({ periodsPerWeek }, { where: { id: req.params.id } });
  res.redirect('/admin');
});
app.post('/admin/user/:id/delete', isAdmin, async (req, res) => {
  await User.destroy({ where: { id: req.params.id } });
  res.redirect('/admin');
});

// Admin reports: summary and CSV export
app.get('/admin/reports', isAdmin, async (req, res) => {
  const { from, to, subject } = req.query;
  const userCounts = await User.findAll({
    attributes: ['role', [sequelize.fn('COUNT', sequelize.col('id')), 'count']],
    group: ['role']
  });
  // Build filter
  const filter = {};
  if (from || to) filter.date = {};
  if (from) filter.date[Op.gte] = from;
  if (to) filter.date[Op.lte] = to;
  if (subject) filter.subject = { [Op.iLike]: `%${subject}%` };
  const totalRecords = await TeachingRecord.count({ where: filter });
  const avgRating = await TeachingRecord.findOne({
    attributes: [[sequelize.fn('AVG', sequelize.col('rating')), 'avg']],
    where: { ...filter, rating: { [Op.ne]: null } }
  });
  // Records per month
  const recordsPerMonth = await TeachingRecord.findAll({
    attributes: [
      [sequelize.fn('to_char', sequelize.col('date'), 'YYYY-MM'), 'month'],
      [sequelize.fn('COUNT', sequelize.col('id')), 'count']
    ],
    where: filter,
    group: [sequelize.fn('to_char', sequelize.col('date'), 'YYYY-MM')],
    order: [[sequelize.fn('to_char', sequelize.col('date'), 'YYYY-MM'), 'ASC']]
  });
  // Avg rating per month
  const avgRatingPerMonth = await TeachingRecord.findAll({
    attributes: [
      [sequelize.fn('to_char', sequelize.col('date'), 'YYYY-MM'), 'month'],
      [sequelize.fn('AVG', sequelize.col('rating')), 'avg']
    ],
    where: { ...filter, rating: { [Op.ne]: null } },
    group: [sequelize.fn('to_char', sequelize.col('date'), 'YYYY-MM')],
    order: [[sequelize.fn('to_char', sequelize.col('date'), 'YYYY-MM'), 'ASC']]
  });
  // Records per subject
  const recordsPerSubject = await TeachingRecord.findAll({
    attributes: [
      'subject',
      [sequelize.fn('COUNT', sequelize.col('id')), 'count']
    ],
    where: filter,
    group: ['subject'],
    order: [[sequelize.fn('COUNT', sequelize.col('id')), 'DESC']]
  });
  // Assigned vs. actual periods per week
  const teachers = await User.findAll({ where: { role: 'teacher' } });
  const periodStats = [];
  for (const teacher of teachers) {
    // Count records for this teacher in the current week
    const weekStart = new Date();
    weekStart.setDate(weekStart.getDate() - weekStart.getDay());
    const weekEnd = new Date(weekStart);
    weekEnd.setDate(weekStart.getDate() + 6);
    const actualPeriods = await TeachingRecord.count({
      where: {
        userId: teacher.id,
        date: { [Op.between]: [weekStart, weekEnd] }
      }
    });
    periodStats.push({
      name: teacher.firstName + ' ' + teacher.lastName,
      assigned: teacher.periodsPerWeek,
      actual: actualPeriods
    });
  }
  // Teacher performance stats
  const teacherStats = [];
  for (const teacher of teachers) {
    const submitted = await TeachingRecord.count({ where: { userId: teacher.id, status: 'submitted' } });
    const avgRatingRow = await TeachingRecord.findOne({
      attributes: [[sequelize.fn('AVG', sequelize.col('rating')), 'avg']],
      where: { userId: teacher.id, rating: { [Op.ne]: null } }
    });
    const avgRating = avgRatingRow && avgRatingRow.get('avg') ? Number(avgRatingRow.get('avg')).toFixed(2) : '-';
    const latest = await TeachingRecord.findOne({
      where: { userId: teacher.id, feedback: { [Op.ne]: null } },
      order: [['updatedAt', 'DESC']]
    });
    teacherStats.push({
      id: teacher.id,
      name: teacher.firstName + ' ' + teacher.lastName,
      email: teacher.email,
      assigned: teacher.periodsPerWeek,
      submitted,
      avgRating,
      feedback: latest ? latest.feedback : '-'
    });
  }
  res.render('admin_reports', {
    userCounts,
    totalRecords,
    avgRating: avgRating ? Number(avgRating.get('avg')).toFixed(2) : 'N/A',
    from,
    to,
    subject,
    recordsPerMonth: recordsPerMonth.map(r => ({ month: r.get('month'), count: Number(r.get('count')) })),
    avgRatingPerMonth: avgRatingPerMonth.map(r => ({ month: r.get('month'), avg: Number(r.get('avg')).toFixed(2) })),
    recordsPerSubject: recordsPerSubject.map(r => ({ subject: r.get('subject'), count: Number(r.get('count')) })),
    periodStats,
    teacherStats
  });
});
// CSV export
app.get('/admin/reports/export', isAdmin, async (req, res) => {
  const records = await TeachingRecord.findAll({ raw: true });
  const parser = new Parser();
  const csv = parser.parse(records);
  res.header('Content-Type', 'text/csv');
  res.attachment('teaching_records.csv');
  res.send(csv);
});

// Headmaster panel: view all records
app.get('/headmaster', isHeadmaster, async (req, res) => {
  const records = await TeachingRecord.findAll({
    order: [['date', 'DESC']],
    include: [{ model: User, attributes: ['firstName', 'lastName'] }]
  });
  // Attach teacherName to each record
  const recordsWithNames = records.map(r => {
    const rec = r.get({ plain: true });
    rec.teacherName = r.User ? r.User.firstName + ' ' + r.User.lastName : '';
    return rec;
  });
  res.render('headmaster_panel', { records: recordsWithNames });
});
// Headmaster: review/feedback/rate
app.get('/headmaster/records/:id', isHeadmaster, async (req, res) => {
  const record = await TeachingRecord.findByPk(req.params.id);
  res.render('headmaster_record', { record, error: null });
});
app.post('/headmaster/records/:id/review', isHeadmaster, async (req, res) => {
  const { feedback, rating } = req.body;
  await TeachingRecord.update({ feedback, rating, status: 'reviewed' }, { where: { id: req.params.id } });
  res.redirect('/headmaster/records/' + req.params.id);
});

// Headmaster reports: summary and CSV export
app.get('/headmaster/reports', isHeadmaster, async (req, res) => {
  const { from, to, subject } = req.query;
  const userCounts = await User.findAll({
    attributes: ['role', [sequelize.fn('COUNT', sequelize.col('id')), 'count']],
    group: ['role']
  });
  const filter = {};
  if (from || to) filter.date = {};
  if (from) filter.date[Op.gte] = from;
  if (to) filter.date[Op.lte] = to;
  if (subject) filter.subject = { [Op.iLike]: `%${subject}%` };
  const totalRecords = await TeachingRecord.count({ where: filter });
  const avgRating = await TeachingRecord.findOne({
    attributes: [[sequelize.fn('AVG', sequelize.col('rating')), 'avg']],
    where: { ...filter, rating: { [Op.ne]: null } }
  });
  const recordsPerMonth = await TeachingRecord.findAll({
    attributes: [
      [sequelize.fn('to_char', sequelize.col('date'), 'YYYY-MM'), 'month'],
      [sequelize.fn('COUNT', sequelize.col('id')), 'count']
    ],
    where: filter,
    group: [sequelize.fn('to_char', sequelize.col('date'), 'YYYY-MM')],
    order: [[sequelize.fn('to_char', sequelize.col('date'), 'YYYY-MM'), 'ASC']]
  });
  const avgRatingPerMonth = await TeachingRecord.findAll({
    attributes: [
      [sequelize.fn('to_char', sequelize.col('date'), 'YYYY-MM'), 'month'],
      [sequelize.fn('AVG', sequelize.col('rating')), 'avg']
    ],
    where: { ...filter, rating: { [Op.ne]: null } },
    group: [sequelize.fn('to_char', sequelize.col('date'), 'YYYY-MM')],
    order: [[sequelize.fn('to_char', sequelize.col('date'), 'YYYY-MM'), 'ASC']]
  });
  const recordsPerSubject = await TeachingRecord.findAll({
    attributes: [
      'subject',
      [sequelize.fn('COUNT', sequelize.col('id')), 'count']
    ],
    where: filter,
    group: ['subject'],
    order: [[sequelize.fn('COUNT', sequelize.col('id')), 'DESC']]
  });
  // Teacher performance stats
  const teachers = await User.findAll({ where: { role: 'teacher' } });
  const teacherStats = [];
  for (const teacher of teachers) {
    const submitted = await TeachingRecord.count({ where: { userId: teacher.id, status: 'submitted' } });
    const avgRatingRow = await TeachingRecord.findOne({
      attributes: [[sequelize.fn('AVG', sequelize.col('rating')), 'avg']],
      where: { userId: teacher.id, rating: { [Op.ne]: null } }
    });
    const avgRating = avgRatingRow && avgRatingRow.get('avg') ? Number(avgRatingRow.get('avg')).toFixed(2) : '-';
    const latest = await TeachingRecord.findOne({
      where: { userId: teacher.id, feedback: { [Op.ne]: null } },
      order: [['updatedAt', 'DESC']]
    });
    teacherStats.push({
      id: teacher.id,
      name: teacher.firstName + ' ' + teacher.lastName,
      email: teacher.email,
      assigned: teacher.periodsPerWeek,
      submitted,
      avgRating,
      feedback: latest ? latest.feedback : '-'
    });
  }
  res.render('headmaster_reports', {
    userCounts,
    totalRecords,
    avgRating: avgRating ? Number(avgRating.get('avg')).toFixed(2) : 'N/A',
    from,
    to,
    subject,
    recordsPerMonth: recordsPerMonth.map(r => ({ month: r.get('month'), count: Number(r.get('count')) })),
    avgRatingPerMonth: avgRatingPerMonth.map(r => ({ month: r.get('month'), avg: Number(r.get('avg')).toFixed(2) })),
    recordsPerSubject: recordsPerSubject.map(r => ({ subject: r.get('subject'), count: Number(r.get('count')) })),
    teacherStats
  });
});
app.get('/headmaster/reports/export', isHeadmaster, async (req, res) => {
  const records = await TeachingRecord.findAll({ raw: true });
  const parser = new Parser();
  const csv = parser.parse(records);
  res.header('Content-Type', 'text/csv');
  res.attachment('teaching_records.csv');
  res.send(csv);
});

// Forgot password - request form
app.get('/forgot-password', forgotLimiter, (req, res) => {
  res.render('forgot_password', { error: null, success: null });
});
app.post('/forgot-password', forgotLimiter, async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.render('forgot_password', { error: 'Please enter your email address.', success: null });
  }
  const user = await User.findOne({ where: { email } });
  if (!user) return res.render('forgot_password', { error: 'No account with that email.', success: null });
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const expires = new Date(Date.now() + 15 * 60 * 1000); // 15 min
  await User.update({ resetPasswordCode: code, resetPasswordExpires: expires }, { where: { id: user.id } });
  // Send email
  await transporter.sendMail({
    from: 'noreply@teaching-system.com',
    to: user.email,
    subject: 'Password Reset Code',
    text: `Your password reset code is: ${code}`
  });
  req.session.resetEmail = email;
  return res.render('verify_code', { error: null, success: 'A code has been sent to your email.' });
});
// Verify code
app.get('/verify-code', codeLimiter, (req, res) => {
  res.render('verify_code', { error: null, success: null });
});
app.post('/verify-code', codeLimiter, async (req, res) => {
  const { code } = req.body;
  const email = req.session.resetEmail;
  if (!email) {
    return res.render('verify_code', { error: 'Session expired. Please start the process again.', success: null });
  }
  const user = await User.findOne({ where: { email } });
  if (!user || !user.resetPasswordCode || !user.resetPasswordExpires) {
    return res.render('verify_code', { error: 'Invalid or expired code.', success: null });
  }
  if (user.resetPasswordCode !== code || new Date() > user.resetPasswordExpires) {
    return res.render('verify_code', { error: 'Invalid or expired code.', success: null });
  }
  req.session.allowReset = true;
  return res.redirect('/reset-password');
});
// Reset password
app.get('/reset-password', resetLimiter, (req, res) => {
  if (!req.session.allowReset) return res.redirect('/forgot-password');
  return res.render('reset_password', { error: null, success: null });
});
app.post('/reset-password', resetLimiter, async (req, res) => {
  if (!req.session.allowReset) return res.redirect('/forgot-password');
  const { password, password2 } = req.body;
  const email = req.session.resetEmail;
  if (!email) {
    return res.render('reset_password', { error: 'Session expired. Please start the process again.', success: null });
  }
  if (!password || password.length < 6) {
    return res.render('reset_password', { error: 'Password must be at least 6 characters.', success: null });
  }
  if (password !== password2) {
    return res.render('reset_password', { error: 'Passwords do not match.', success: null });
  }
  const hash = await bcrypt.hash(password, 10);
  await User.update({ password: hash, resetPasswordCode: null, resetPasswordExpires: null }, { where: { email } });
  req.session.allowReset = false;
  req.session.resetEmail = null;
  return res.render('reset_password', { error: null, success: 'Password has been reset. You can now log in.' });
});

// Error handler
app.use((err, req, res, next) => {
  res.status(500).send('Server error');
});

// Sync DB and start
sequelize.sync().then(() => {
  app.listen(3001, () => console.log('Simple app running on http://localhost:3001'));
}); 