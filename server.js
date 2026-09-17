const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'CHANGE_THIS_IN_PRODUCTION';

const db = new Database('newcarcare.db');
db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS customers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  phone TEXT NOT NULL UNIQUE,
  email TEXT UNIQUE,
  password_hash TEXT NOT NULL,
  car_brand TEXT,
  car_model TEXT,
  car_number TEXT,
  joined_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS services (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  customer_id INTEGER NOT NULL,
  service_date TEXT NOT NULL,
  service_type TEXT NOT NULL,
  amount REAL NOT NULL DEFAULT 0,
  notes TEXT DEFAULT '',
  FOREIGN KEY(customer_id) REFERENCES customers(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS job_cards (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  customer_id INTEGER NOT NULL,
  opened_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  complaint TEXT DEFAULT '',
  condition_notes TEXT DEFAULT '',
  status TEXT NOT NULL DEFAULT 'OPEN',
  FOREIGN KEY(customer_id) REFERENCES customers(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS inventory (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  item_name TEXT NOT NULL UNIQUE,
  quantity REAL NOT NULL DEFAULT 0,
  unit TEXT NOT NULL DEFAULT 'pcs',
  low_stock_level REAL NOT NULL DEFAULT 2
);
CREATE TABLE IF NOT EXISTS reminders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  customer_id INTEGER NOT NULL,
  next_service_km INTEGER,
  due_note TEXT DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(customer_id) REFERENCES customers(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS feedback (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  customer_id INTEGER NOT NULL,
  rating INTEGER NOT NULL,
  message TEXT DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(customer_id) REFERENCES customers(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS vehicles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  customer_id INTEGER NOT NULL,
  brand TEXT DEFAULT '',
  model TEXT DEFAULT '',
  registration_no TEXT NOT NULL,
  year INTEGER,
  fuel_type TEXT DEFAULT '',
  FOREIGN KEY(customer_id) REFERENCES customers(id) ON DELETE CASCADE,
  UNIQUE(customer_id, registration_no)
);
CREATE TABLE IF NOT EXISTS estimates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  customer_id INTEGER NOT NULL,
  vehicle_id INTEGER,
  estimate_no TEXT NOT NULL UNIQUE,
  estimated_amount REAL NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'PENDING',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(customer_id) REFERENCES customers(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  service_id INTEGER NOT NULL,
  amount REAL NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'PENDING',
  paid_at TEXT,
  FOREIGN KEY(service_id) REFERENCES services(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS staff (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1
);
`);

try { db.exec("ALTER TABLE services ADD COLUMN current_km INTEGER"); } catch(e) {}
try { db.exec("ALTER TABLE services ADD COLUMN next_service_km INTEGER"); } catch(e) {}
try { db.exec("ALTER TABLE services ADD COLUMN bill_no TEXT"); } catch(e) {}
try { db.exec("ALTER TABLE services ADD COLUMN estimate_amount REAL"); } catch(e) {}
try { db.exec("ALTER TABLE services ADD COLUMN payment_status TEXT"); } catch(e) {}
try { db.exec("ALTER TABLE services ADD COLUMN payment_amount REAL"); } catch(e) {}
const adminExists = db.prepare('SELECT id FROM admins WHERE email=?').get('admin@newcarcare.local');
if (!adminExists) {
  db.prepare('INSERT INTO admins(email,password_hash) VALUES(?,?)')
    .run('admin@newcarcare.local', bcrypt.hashSync('ChangeMe123!', 12));
}

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function tokenFor(user) {
  return jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
}
function auth(req, res, next) {
  try {
    const h = req.headers.authorization || '';
    if (!h.startsWith('Bearer ')) throw new Error();
    req.user = jwt.verify(h.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Please login again.' });
  }
}
function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required.' });
  next();
}

app.post('/api/register', async (req,res) => {
  try {
    const {name,phone,email,password,carBrand,carModel,carNumber} = req.body;
    if (!name || !phone || !password) return res.status(400).json({error:'Name, phone and password are required.'});
    if (password.length < 6) return res.status(400).json({error:'Password must be at least 6 characters.'});
    const hash = await bcrypt.hash(password, 12);
    const info = db.prepare(`INSERT INTO customers(name,phone,email,password_hash,car_brand,car_model,car_number)
      VALUES(?,?,?,?,?,?,?)`).run(name.trim(),phone.trim(),email?.trim()||null,hash,carBrand||'',carModel||'',carNumber||'');
    const user = {id:info.lastInsertRowid, role:'customer'};
    res.json({token:tokenFor(user), user});
  } catch(e) {
    res.status(400).json({error: e.message.includes('UNIQUE') ? 'Phone or email is already registered.' : 'Registration failed.'});
  }
});

app.post('/api/login', async (req,res) => {
  const {phone,password} = req.body;
  const customer = db.prepare('SELECT * FROM customers WHERE phone=?').get(phone||'');
  if (!customer || !(await bcrypt.compare(password||'', customer.password_hash)))
    return res.status(401).json({error:'Invalid phone number or password.'});
  res.json({token:tokenFor({id:customer.id,role:'customer'}), user:{id:customer.id,role:'customer'}});
});

app.post('/api/admin/login', async (req,res) => {
  const {email,password} = req.body;
  const admin = db.prepare('SELECT * FROM admins WHERE email=?').get(email||'');
  if (!admin || !(await bcrypt.compare(password||'', admin.password_hash)))
    return res.status(401).json({error:'Invalid admin credentials.'});
  res.json({token:tokenFor({id:admin.id,role:'admin'})});
});

app.get('/api/me', auth, (req,res) => {
  if (req.user.role !== 'customer') return res.status(403).json({error:'Customer endpoint.'});
  const c = db.prepare(`SELECT id,name,phone,email,car_brand,car_model,car_number,joined_at FROM customers WHERE id=?`).get(req.user.id);
  const services = db.prepare(`SELECT id,service_date,service_type,amount,notes FROM services WHERE customer_id=? ORDER BY service_date DESC, id DESC`).all(req.user.id);
  const total = services.reduce((s,x)=>s+Number(x.amount||0),0);
  res.json({customer:c, services, stats:{
    visits:services.length,
    totalSpent:total,
    lastService:services[0]?.service_date || null
  }});
});

app.get('/api/admin/customers', auth, adminOnly, (req,res) => {
  const rows = db.prepare(`
    SELECT c.id,c.name,c.phone,c.email,c.car_brand,c.car_model,c.car_number,c.joined_at,
      COUNT(s.id) visits, COALESCE(SUM(s.amount),0) total_spent, MAX(s.service_date) last_service
    FROM customers c LEFT JOIN services s ON s.customer_id=c.id
    GROUP BY c.id ORDER BY c.joined_at DESC`).all();
  res.json(rows);
});

app.get('/api/admin/customers/:id', auth, adminOnly, (req,res) => {
  const c = db.prepare(`SELECT id,name,phone,email,car_brand,car_model,car_number,joined_at FROM customers WHERE id=?`).get(req.params.id);
  if (!c) return res.status(404).json({error:'Customer not found.'});
  const services = db.prepare(`SELECT * FROM services WHERE customer_id=? ORDER BY service_date DESC,id DESC`).all(req.params.id);
  res.json({customer:c,services});
});

app.post('/api/admin/services', auth, adminOnly, (req,res) => {
  const {customerId,serviceDate,serviceType,amount,notes} = req.body;
  if (!customerId || !serviceDate || !serviceType) return res.status(400).json({error:'Customer, date and service type are required.'});
  const billNo = 'NCC-' + Date.now().toString().slice(-8);
  db.prepare(`INSERT INTO services(customer_id,service_date,service_type,amount,notes,current_km,next_service_km,bill_no)
    VALUES(?,?,?,?,?,?,?,?)`).run(customerId,serviceDate,serviceType,Number(amount||0),notes||'',Number(req.body.currentKm||0)||null,Number(req.body.nextServiceKm||0)||null,billNo);
  if (req.body.nextServiceKm) {
    db.prepare(`INSERT INTO reminders(customer_id,next_service_km,due_note) VALUES(?,?,?)`)
      .run(customerId,Number(req.body.nextServiceKm),'Next service reminder');
  }
  res.json({ok:true,billNo});
});


app.post('/api/admin/job-cards', auth, adminOnly, (req,res)=>{
  const {customerId,complaint,conditionNotes}=req.body;
  if(!customerId) return res.status(400).json({error:'Customer is required.'});
  const x=db.prepare(`INSERT INTO job_cards(customer_id,complaint,condition_notes) VALUES(?,?,?)`).run(customerId,complaint||'',conditionNotes||'');
  res.json({ok:true,id:x.lastInsertRowid});
});
app.get('/api/admin/job-cards', auth, adminOnly, (req,res)=>{
  res.json(db.prepare(`SELECT j.*,c.name,c.phone,c.car_brand,c.car_model,c.car_number
    FROM job_cards j JOIN customers c ON c.id=j.customer_id ORDER BY j.id DESC`).all());
});
app.post('/api/admin/inventory', auth, adminOnly, (req,res)=>{
  const {itemName,quantity,unit,lowStockLevel}=req.body;
  if(!itemName) return res.status(400).json({error:'Item name is required.'});
  db.prepare(`INSERT INTO inventory(item_name,quantity,unit,low_stock_level) VALUES(?,?,?,?)
    ON CONFLICT(item_name) DO UPDATE SET quantity=excluded.quantity,unit=excluded.unit,low_stock_level=excluded.low_stock_level`)
    .run(itemName,Number(quantity||0),unit||'pcs',Number(lowStockLevel||2));
  res.json({ok:true});
});
app.get('/api/admin/inventory', auth, adminOnly, (req,res)=>{
  res.json(db.prepare(`SELECT *, quantity<=low_stock_level AS low_stock FROM inventory ORDER BY item_name`).all());
});
app.post('/api/customer/feedback', auth, (req,res)=>{
  if(req.user.role!=='customer') return res.status(403).json({error:'Customer access required.'});
  const {rating,message}=req.body;
  if(!rating || rating<1 || rating>5) return res.status(400).json({error:'Rating must be 1-5.'});
  db.prepare(`INSERT INTO feedback(customer_id,rating,message) VALUES(?,?,?)`).run(req.user.id,Number(rating),message||'');
  res.json({ok:true});
});


app.get('/api/admin/stats', auth, adminOnly, (req,res)=>{
  const totalCustomers=db.prepare('SELECT COUNT(*) c FROM customers').get().c;
  const totalServices=db.prepare('SELECT COUNT(*) c FROM services').get().c;
  const totalCollected=db.prepare("SELECT COALESCE(SUM(amount),0) x FROM payments WHERE status='PAID'").get().x;
  const pending=db.prepare("SELECT COALESCE(SUM(amount),0) x FROM services WHERE payment_status IN ('PENDING','PARTIAL')").get().x;
  const jobs=db.prepare("SELECT status,COUNT(*) c FROM job_cards GROUP BY status").all();
  res.json({totalCustomers,totalServices,totalCollected,pending,jobs});
});
app.post('/api/admin/vehicles', auth, adminOnly, (req,res)=>{
  const {customerId,brand,model,registrationNo,year,fuelType}=req.body;
  if(!customerId||!registrationNo) return res.status(400).json({error:'Customer and registration number are required.'});
  try {
    const x=db.prepare(`INSERT INTO vehicles(customer_id,brand,model,registration_no,year,fuel_type) VALUES(?,?,?,?,?,?)`)
      .run(customerId,brand||'',model||'',registrationNo.toUpperCase(),year||null,fuelType||'');
    res.json({ok:true,id:x.lastInsertRowid});
  } catch(e){res.status(400).json({error:'This vehicle is already registered for the customer.'});}
});
app.get('/api/admin/vehicles/:customerId', auth, adminOnly, (req,res)=>{
  res.json(db.prepare('SELECT * FROM vehicles WHERE customer_id=? ORDER BY id DESC').all(req.params.customerId));
});
app.post('/api/admin/estimates', auth, adminOnly, (req,res)=>{
  const {customerId,vehicleId,estimatedAmount}=req.body;
  const no='EST-'+Date.now().toString().slice(-8);
  db.prepare(`INSERT INTO estimates(customer_id,vehicle_id,estimate_no,estimated_amount) VALUES(?,?,?,?)`)
    .run(customerId,vehicleId||null,estimatedAmount||0,no);
  res.json({ok:true,estimateNo:no});
});
app.post('/api/admin/payments', auth, adminOnly, (req,res)=>{
  const {serviceId,amount,status}=req.body;
  db.prepare(`INSERT INTO payments(service_id,amount,status,paid_at) VALUES(?,?,?,CASE WHEN ?='PAID' THEN CURRENT_TIMESTAMP ELSE NULL END)`)
    .run(serviceId,Number(amount||0),status||'PENDING',status||'PENDING');
  db.prepare(`UPDATE services SET payment_status=?, payment_amount=? WHERE id=?`).run(status||'PENDING',Number(amount||0),serviceId);
  res.json({ok:true});
});

app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.listen(PORT,()=>console.log(`New Car Care running at http://localhost:${PORT}`));
