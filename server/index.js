import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '..');
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const PROJECTS_FILE = path.join(DATA_DIR, 'projects.json');

const PORT = Number(process.env.PORT || 8787);
const JWT_SECRET = process.env.JWT_SECRET || 'change-me-in-production';

const app = express();
app.use(cors());
app.use(express.json({ limit: '1mb' }));

async function ensureDataFile() {
  await fs.mkdir(DATA_DIR, { recursive: true });
  try {
    await fs.access(USERS_FILE);
  } catch {
    await fs.writeFile(USERS_FILE, JSON.stringify({ users: [] }, null, 2), 'utf8');
  }
  try {
    await fs.access(PROJECTS_FILE);
  } catch {
    await fs.writeFile(PROJECTS_FILE, JSON.stringify({ projects: [] }, null, 2), 'utf8');
  }
}

async function readUsers() {
  const raw = await fs.readFile(USERS_FILE, 'utf8');
  const parsed = JSON.parse(raw);
  return Array.isArray(parsed.users) ? parsed.users : [];
}

async function writeUsers(users) {
  await fs.writeFile(USERS_FILE, JSON.stringify({ users }, null, 2), 'utf8');
}

async function readProjects() {
  const raw = await fs.readFile(PROJECTS_FILE, 'utf8');
  const parsed = JSON.parse(raw);
  return Array.isArray(parsed.projects) ? parsed.projects : [];
}

async function writeProjects(projects) {
  await fs.writeFile(PROJECTS_FILE, JSON.stringify({ projects }, null, 2), 'utf8');
}

function signToken(user) {
  return jwt.sign({ sub: user.id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
}

function mapSafeUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    createdAt: user.createdAt
  };
}

function mapProjectForUser(project, userId) {
  const membership = project.members.find((m) => m.userId === userId);
  return {
    id: project.id,
    name: project.name,
    role: membership?.role || 'viewer',
    ownerId: project.ownerId,
    createdAt: project.createdAt,
    updatedAt: project.updatedAt
  };
}

function getMembership(project, userId) {
  return project.members.find((m) => m.userId === userId) || null;
}

function canWriteProject(role) {
  return role === 'owner' || role === 'editor';
}

function authRequired(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (!token) return res.status(401).json({ error: 'Требуется авторизация.' });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch {
    res.status(401).json({ error: 'Недействительный токен.' });
  }
}

app.post('/api/auth/register', async (req, res) => {
  try {
    const name = String(req.body.name || '').trim();
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');

    if (name.length < 2) return res.status(400).json({ error: 'Имя должно быть не короче 2 символов.' });
    if (!email.includes('@')) return res.status(400).json({ error: 'Некорректный email.' });
    if (password.length < 8) return res.status(400).json({ error: 'Пароль должен быть не короче 8 символов.' });

    const users = await readUsers();
    const exists = users.some((u) => u.email === email);
    if (exists) return res.status(409).json({ error: 'Пользователь с таким email уже существует.' });

    const passwordHash = await bcrypt.hash(password, 10);
    const user = {
      id: crypto.randomUUID(),
      name,
      email,
      passwordHash,
      createdAt: new Date().toISOString()
    };

    users.push(user);
    await writeUsers(users);

    const token = signToken(user);
    res.status(201).json({ token, user: mapSafeUser(user) });
  } catch {
    res.status(500).json({ error: 'Ошибка регистрации.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');

    const users = await readUsers();
    const user = users.find((u) => u.email === email);
    if (!user) return res.status(401).json({ error: 'Неверный email или пароль.' });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Неверный email или пароль.' });

    const token = signToken(user);
    res.json({ token, user: mapSafeUser(user) });
  } catch {
    res.status(500).json({ error: 'Ошибка входа.' });
  }
});

app.get('/api/auth/me', authRequired, async (req, res) => {
  try {
    const users = await readUsers();
    const user = users.find((u) => u.id === req.user.sub);
    if (!user) return res.status(404).json({ error: 'Пользователь не найден.' });
    res.json({ user: mapSafeUser(user) });
  } catch {
    res.status(500).json({ error: 'Ошибка загрузки профиля.' });
  }
});

app.get('/api/projects', authRequired, async (req, res) => {
  try {
    const projects = await readProjects();
    const visible = projects
      .filter((project) => getMembership(project, req.user.sub))
      .map((project) => mapProjectForUser(project, req.user.sub));
    res.json({ projects: visible });
  } catch {
    res.status(500).json({ error: 'Ошибка загрузки проектов.' });
  }
});

app.post('/api/projects', authRequired, async (req, res) => {
  try {
    const name = String(req.body.name || '').trim();
    if (name.length < 3) return res.status(400).json({ error: 'Название проекта должно быть не короче 3 символов.' });

    const projects = await readProjects();
    const now = new Date().toISOString();
    const project = {
      id: crypto.randomUUID(),
      name,
      ownerId: req.user.sub,
      createdAt: now,
      updatedAt: now,
      members: [{ userId: req.user.sub, role: 'owner' }],
      session: null
    };

    projects.push(project);
    await writeProjects(projects);
    res.status(201).json({ project: mapProjectForUser(project, req.user.sub) });
  } catch {
    res.status(500).json({ error: 'Ошибка создания проекта.' });
  }
});

app.post('/api/projects/:projectId/members', authRequired, async (req, res) => {
  try {
    const projectId = String(req.params.projectId || '');
    const email = String(req.body.email || '').trim().toLowerCase();
    const role = String(req.body.role || 'viewer').toLowerCase();
    if (!['editor', 'viewer'].includes(role)) return res.status(400).json({ error: 'Роль должна быть editor или viewer.' });
    if (!email.includes('@')) return res.status(400).json({ error: 'Некорректный email.' });

    const users = await readUsers();
    const invitee = users.find((u) => u.email === email);
    if (!invitee) return res.status(404).json({ error: 'Пользователь с таким email не найден.' });

    const projects = await readProjects();
    const project = projects.find((p) => p.id === projectId);
    if (!project) return res.status(404).json({ error: 'Проект не найден.' });

    const actorMembership = getMembership(project, req.user.sub);
    if (!actorMembership || actorMembership.role !== 'owner') {
      return res.status(403).json({ error: 'Только владелец может управлять доступом.' });
    }

    const existing = getMembership(project, invitee.id);
    if (existing) {
      existing.role = role;
    } else {
      project.members.push({ userId: invitee.id, role });
    }
    project.updatedAt = new Date().toISOString();
    await writeProjects(projects);

    res.json({
      added: { id: invitee.id, email: invitee.email, name: invitee.name, role },
      project: mapProjectForUser(project, req.user.sub)
    });
  } catch {
    res.status(500).json({ error: 'Ошибка выдачи доступа.' });
  }
});

app.get('/api/projects/:projectId/session', authRequired, async (req, res) => {
  try {
    const projectId = String(req.params.projectId || '');
    const projects = await readProjects();
    const project = projects.find((p) => p.id === projectId);
    if (!project) return res.status(404).json({ error: 'Проект не найден.' });

    const membership = getMembership(project, req.user.sub);
    if (!membership) return res.status(403).json({ error: 'Нет доступа к проекту.' });

    res.json({
      project: mapProjectForUser(project, req.user.sub),
      session: project.session || null
    });
  } catch {
    res.status(500).json({ error: 'Ошибка загрузки сессии проекта.' });
  }
});

app.put('/api/projects/:projectId/session', authRequired, async (req, res) => {
  try {
    const projectId = String(req.params.projectId || '');
    const session = req.body.session;
    if (!session || typeof session !== 'object') {
      return res.status(400).json({ error: 'Некорректный формат данных сессии.' });
    }

    const projects = await readProjects();
    const project = projects.find((p) => p.id === projectId);
    if (!project) return res.status(404).json({ error: 'Проект не найден.' });

    const membership = getMembership(project, req.user.sub);
    if (!membership) return res.status(403).json({ error: 'Нет доступа к проекту.' });
    if (!canWriteProject(membership.role)) {
      return res.status(403).json({ error: 'У вас только режим просмотра.' });
    }

    project.session = session;
    project.updatedAt = new Date().toISOString();
    await writeProjects(projects);
    res.json({ ok: true, updatedAt: project.updatedAt });
  } catch {
    res.status(500).json({ error: 'Ошибка сохранения сессии проекта.' });
  }
});

app.use(express.static(ROOT_DIR));
app.get('/', (_req, res) => {
  res.sendFile(path.join(ROOT_DIR, 'ip-camera-testing.html'));
});

await ensureDataFile();
app.listen(PORT, () => {
  console.log(`Server started on http://localhost:${PORT}`);
});
