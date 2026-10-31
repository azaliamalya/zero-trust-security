require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const db = require('../database/db');
const app = express();
app.use(express.json());
const PORT = Number(process.env.PORT_TRANSKRIP || 3002);
const JWT_SECRET = process.env.JWT_SECRET || 'local-demo-change-this-jwt-secret';
const GATEWAY_SECRET = process.env.GATEWAY_SECRET || 'local-demo-change-this-gateway-secret';

function verifyGateway(req,res,next) {
  if (req.headers['x-gateway-secret'] !== GATEWAY_SECRET) return res.status(403).json({error:'Gateway secret tidak valid; akses langsung ditolak'});
  const h=req.headers.authorization||'';
  if(!h.startsWith('Bearer ')) return res.status(401).json({error:'Token wajib diteruskan gateway'});
  try {
    req.tokenPayload=jwt.verify(h.slice(7),JWT_SECRET);
    req.userContext=JSON.parse(Buffer.from(req.headers['x-auth-context']||'','base64').toString('utf8')||'{}');
    next();
  } catch { return res.status(401).json({error:'Token tidak valid atau kedaluwarsa'}); }
}
app.get('/health',(_req,res)=>res.json({ok:true,service:'transkrip'}));
app.use(verifyGateway);
app.get('/transkrip/:nim',(req,res)=>{
  const p=req.tokenPayload,u=req.userContext,nim=req.params.nim;
  if(p.role==='service') return res.status(403).json({error:'Token service tidak digunakan untuk membaca transkrip'});
  if(u.role==='mahasiswa'&&u.nim!==nim) return res.status(403).json({error:'Mahasiswa hanya boleh melihat transkrip miliknya'});
  if(!['mahasiswa','admin'].includes(u.role)) return res.status(403).json({error:'Role tidak boleh melihat transkrip'});
  const student=db.prepare('SELECT id,nim,full_name FROM users WHERE nim=?').get(nim);
  if(!student) return res.status(404).json({error:'Mahasiswa tidak ditemukan'});
  const rows=db.prepare(`SELECT t.class_id,c.class_name,c.course_name,t.grade,t.synced_at
                         FROM transcripts t JOIN classes c ON c.id=t.class_id
                         WHERE t.student_id=? ORDER BY c.id`).all(student.id);
  res.json({student,transcripts:rows});
});
app.post('/transkrip/sinkron',(req,res)=>{
  if(req.tokenPayload.role!=='service'||req.tokenPayload.sub!=='service-nilai') return res.status(403).json({error:'Hanya token service-nilai yang diizinkan'});
  const classId=Number(req.body?.kelasId);
  const cls=db.prepare('SELECT * FROM classes WHERE id=?').get(classId);
  if(!cls) return res.status(404).json({error:'Kelas tidak ditemukan'});
  if(!cls.is_final) return res.status(409).json({error:'Kelas harus difinalisasi sebelum sinkronisasi'});
  const sync=db.transaction(()=>{
    const rows=db.prepare('SELECT student_id,grade FROM grades WHERE class_id=?').all(classId);
    const upsert=db.prepare(`INSERT INTO transcripts(student_id,class_id,grade,synced_at) VALUES (?,?,?,CURRENT_TIMESTAMP)
                             ON CONFLICT(student_id,class_id) DO UPDATE SET grade=excluded.grade,synced_at=CURRENT_TIMESTAMP`);
    rows.forEach(r=>upsert.run(r.student_id,classId,r.grade));
    return rows.length;
  });
  const count=sync();
  res.json({message:'Sinkronisasi berhasil',kelasId:classId,jumlahTranskrip:count});
});
app.listen(PORT,()=>console.log(`Service Transkrip berjalan di http://localhost:${PORT}`));

