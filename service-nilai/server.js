require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const db = require('../database/db');
const app = express();
app.use(express.json());
const PORT = Number(process.env.PORT_NILAI || 3001);
const JWT_SECRET = process.env.JWT_SECRET || 'local-demo-change-this-jwt-secret';
const GATEWAY_SECRET = process.env.GATEWAY_SECRET || 'local-demo-change-this-gateway-secret';

function verifyGateway(req,res,next) {
  if (req.headers['x-gateway-secret'] !== GATEWAY_SECRET) return res.status(403).json({error:'Gateway secret tidak valid; akses langsung ditolak'});
  const h = req.headers.authorization || '';
  if (!h.startsWith('Bearer ')) return res.status(401).json({error:'Token wajib diteruskan gateway'});
  try {
    req.tokenPayload = jwt.verify(h.slice(7),JWT_SECRET);
    req.userContext = JSON.parse(Buffer.from(req.headers['x-auth-context'] || '', 'base64').toString('utf8') || '{}');
    next();
  } catch { return res.status(401).json({error:'Token tidak valid atau kedaluwarsa'}); }
}
app.get('/health',(_req,res)=>res.json({ok:true,service:'nilai'}));
app.use(verifyGateway);

app.get('/nilai',(req,res)=>{
  const u = req.userContext;
  let rows;
  if (req.tokenPayload.role === 'service') return res.status(403).json({error:'Token service tidak digunakan untuk membaca nilai'});
  if (u.role === 'mahasiswa') {
    rows = db.prepare(`SELECT g.id,c.class_name,c.course_name,g.grade,c.is_final FROM grades g
                       JOIN classes c ON c.id=g.class_id WHERE g.student_id=?`).all(u.id);
  } else if (u.role === 'dosen') {
    rows = db.prepare(`SELECT g.id,c.class_name,c.course_name,g.grade,c.is_final,s.nim,s.full_name AS student
                       FROM grades g JOIN classes c ON c.id=g.class_id JOIN users s ON s.id=g.student_id
                       WHERE c.lecturer_id=?`).all(u.id);
  } else return res.status(403).json({error:'Role tidak boleh melihat nilai'});
  res.json(rows);
});
app.put('/nilai/:id',(req,res)=>{
  const p = req.tokenPayload, u = req.userContext;
  if (p.role !== 'dosen' || u.role !== 'dosen') return res.status(403).json({error:'Hanya dosen yang boleh mengubah nilai'});
  const grade = Number(req.body?.nilai);
  if (!Number.isFinite(grade) || grade<0 || grade>100) return res.status(400).json({error:'nilai harus angka 0 sampai 100'});
  const row = db.prepare(`SELECT g.id,c.lecturer_id,c.is_final FROM grades g JOIN classes c ON c.id=g.class_id WHERE g.id=?`).get(Number(req.params.id));
  if (!row) return res.status(404).json({error:'Nilai tidak ditemukan'});
  if (row.lecturer_id !== Number(u.id)) return res.status(403).json({error:'Kelas bukan kelas yang diampu dosen'});
  if (row.is_final) return res.status(403).json({error:'Nilai sudah final'});
  db.prepare('UPDATE grades SET grade=? WHERE id=?').run(grade,row.id);
  res.json({message:'Nilai berhasil diperbarui',id:row.id,nilai:grade});
});
app.post('/kelas/:id/finalisasi',async(req,res)=>{
  const u=req.userContext;
  if(req.tokenPayload.role!=='dosen'||u.role!=='dosen') return res.status(403).json({error:'Hanya dosen yang boleh finalisasi'});
  const cls=db.prepare('SELECT * FROM classes WHERE id=?').get(Number(req.params.id));
  if(!cls) return res.status(404).json({error:'Kelas tidak ditemukan'});
  if(cls.lecturer_id!==Number(u.id)) return res.status(403).json({error:'Kelas bukan kelas yang diampu dosen'});
  if(cls.is_final) return res.status(409).json({error:'Kelas sudah final'});
  db.prepare('UPDATE classes SET is_final=1 WHERE id=?').run(cls.id);
  // Sinkronisasi dilakukan melalui gateway menggunakan token service.
  try {
    const gateway = `http://127.0.0.1:${process.env.PORT_GATEWAY || 3000}`;
    const tokenResp = await fetch(`${gateway}/auth/service`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body:JSON.stringify({
        clientId:process.env.SERVICE_CLIENT_ID || 'service-nilai',
        clientSecret:process.env.SERVICE_CLIENT_SECRET || 'nilai-service-demo-secret'
      })
    });
    if(!tokenResp.ok) throw new Error('Gagal memperoleh token service dari gateway');
    const {accessToken}=await tokenResp.json();
    const syncResp=await fetch(`${gateway}/transkrip/sinkron`,{
      method:'POST',headers:{'Content-Type':'application/json','Authorization':`Bearer ${accessToken}`},
      body:JSON.stringify({kelasId:cls.id})
    });
    const syncBody=await syncResp.json();
    if(!syncResp.ok) throw new Error(syncBody.error || 'Sinkronisasi gagal');
    return res.json({message:'Kelas difinalisasi dan transkrip disinkronkan',kelasId:cls.id,transkrip:syncBody});
  }catch(e){
    return res.status(502).json({message:'Kelas telah difinalisasi, tetapi sinkronisasi transkrip gagal',detail:e.message,kelasId:cls.id});
  }
});
app.listen(PORT,()=>console.log(`Service Nilai berjalan di http://localhost:${PORT}`));

