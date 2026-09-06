const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const users = new Map();
const sessions = new Map();
const online = new Map();
const rooms = new Map();

function json(res, code, data){
  const body=JSON.stringify(data);
  res.writeHead(code, {'Content-Type':'application/json; charset=utf-8','Access-Control-Allow-Origin':'*','Cache-Control':'no-store'});
  res.end(body);
}
function body(req){return new Promise((resolve,reject)=>{let s='';req.on('data',c=>{s+=c;if(s.length>1e6)req.destroy();});req.on('end',()=>{try{resolve(JSON.parse(s||'{}'))}catch(e){reject(e)}});req.on('error',reject)})}
function hashPassword(password,salt=crypto.randomBytes(16).toString('hex')){
  return new Promise((resolve,reject)=>crypto.scrypt(password,salt,64,(e,key)=>e?reject(e):resolve({salt,hash:key.toString('hex')})));
}
function verifyPassword(password,u){
  return new Promise((resolve,reject)=>crypto.scrypt(password,u.salt,64,(e,key)=>e?reject(e):resolve(crypto.timingSafeEqual(Buffer.from(u.hash,'hex'),key))));
}
function token(){return crypto.randomBytes(32).toString('hex')}
function auth(req){const t=(req.headers.authorization||'').replace(/^Bearer\s+/,'');return sessions.get(t)}
function safeUser(u){return {id:u.id,username:u.username,level:u.level||1,rank:u.rank||'برونزي'}}
function roomCode(){let c;do c=crypto.randomBytes(3).toString('hex').toUpperCase();while(rooms.has(c));return c}

const server=http.createServer(async(req,res)=>{
  if(req.method==='OPTIONS'){res.writeHead(204,{'Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'Content-Type, Authorization'});return res.end()}
  const url=new URL(req.url,'http://localhost');
  try{
    if(req.method==='GET' && url.pathname==='/api/online'){
      const now=Date.now(); for(const [id,p] of online) if(now-p.lastSeen>30000) online.delete(id);
      return json(res,200,[...online.values()].map(p=>({id:p.id,name:p.name,room:p.room||null})));
    }
    if(req.method==='POST' && url.pathname==='/api/online'){
      const d=await body(req); const id=d.id||crypto.randomBytes(6).toString('hex');
      online.set(id,{id,name:String(d.name||'لاعب').slice(0,20),room:d.room||null,lastSeen:Date.now()});
      return json(res,200,{ok:true,id});
    }
    if(req.method==='POST' && url.pathname==='/api/auth/register'){
      const d=await body(req); const username=String(d.username||'').trim(); const password=String(d.password||'');
      if(!/^[\p{L}\p{N}_ -]{3,20}$/u.test(username)||password.length<8)return json(res,400,{error:'weak_credentials'});
      const key=username.toLowerCase(); if(users.has(key))return json(res,409,{error:'username_taken'});
      const hp=await hashPassword(password); const u={id:crypto.randomUUID(),username,salt:hp.salt,hash:hp.hash,level:1,rank:'برونزي',createdAt:Date.now()}; users.set(key,u);
      const t=token(); sessions.set(t,u.id); return json(res,200,{token:t,user:safeUser(u)});
    }
    if(req.method==='POST' && url.pathname==='/api/auth/login'){
      const d=await body(req); const u=users.get(String(d.username||'').trim().toLowerCase());
      if(!u)return json(res,401,{error:'account_not_found'}); if(!(await verifyPassword(String(d.password||''),u)))return json(res,401,{error:'invalid_credentials'});
      const t=token();sessions.set(t,u.id);return json(res,200,{token:t,user:safeUser(u)});
    }
    if(req.method==='GET' && url.pathname==='/api/player/me'){
      const id=auth(req); if(!id)return json(res,401,{error:'unauthorized'}); const u=[...users.values()].find(x=>x.id===id); if(!u)return json(res,401,{error:'unauthorized'}); return json(res,200,{user:safeUser(u)});
    }
    if(req.method==='POST' && url.pathname==='/api/player/save'){
      const id=auth(req); if(!id)return json(res,401,{error:'unauthorized'}); const u=[...users.values()].find(x=>x.id===id); if(!u)return json(res,401,{error:'unauthorized'});
      const d=await body(req); if(Number.isFinite(d.level))u.level=Math.max(1,Math.min(999,Number(d.level))); if(typeof d.rank==='string')u.rank=d.rank; return json(res,200,{ok:true,user:safeUser(u)});
    }
    // Static client
    if(req.method==='GET'){
      const file=url.pathname==='/'?path.join(ROOT,'index.html'):path.join(ROOT,url.pathname.replace(/^\//,''));
      if(!file.startsWith(ROOT))return json(res,403,{error:'forbidden'});
      if(fs.existsSync(file)&&fs.statSync(file).isFile()){
        const ext=path.extname(file); const types={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8'};
        res.writeHead(200,{'Content-Type':types[ext]||'application/octet-stream'});return fs.createReadStream(file).pipe(res);
      }
    }
    json(res,404,{error:'not_found'});
  }catch(e){console.error(e);json(res,500,{error:'server_error'})}
});

const wss=new WebSocketServer({server});
function send(ws,msg){if(ws.readyState===1)ws.send(JSON.stringify(msg))}
function broadcast(room,msg,except){const r=rooms.get(room);if(!r)return;for(const c of r.clients)if(c!==except)send(c,msg)}
function leave(ws){
  const room=ws.room;if(room&&rooms.has(room)){const r=rooms.get(room);r.clients.delete(ws);broadcast(room,{type:'peer_left',id:ws.playerId});if(!r.clients.size)rooms.delete(room)}
  if(ws.playerId)online.delete(ws.playerId);
}
wss.on('connection',ws=>{
  ws.on('message',raw=>{
    let m;try{m=JSON.parse(raw)}catch{return}
    if(m.type==='join'){
      const code=String(m.room||'').toUpperCase();if(!rooms.has(code))rooms.set(code,{clients:new Set(),host:null});
      const r=rooms.get(code); if(r.clients.size>=8)return send(ws,{type:'error',message:'room_full'});
      ws.room=code;ws.playerId=String(m.id||crypto.randomBytes(6).toString('hex'));ws.name=String(m.name||'لاعب').slice(0,20);
      if(!r.host)r.host=ws.playerId;r.clients.add(ws);
      send(ws,{type:'joined',room:code,host:r.host===ws.playerId,players:[...r.clients].filter(c=>c!==ws).map(c=>({id:c.playerId,name:c.name}))});
      broadcast(code,{type:'peer_joined',player:{id:ws.playerId,name:ws.name}},ws);return;
    }
    if(m.type==='start'&&ws.room){broadcast(ws.room,{type:'start'});return}
    if(m.type==='state'&&ws.room){
      broadcast(ws.room,{type:'state',player:{id:ws.playerId,name:ws.name,x:Number(m.x)||0,y:Number(m.y)||0,z:Number(m.z)||0,yaw:Number(m.yaw)||0,skin:Number(m.skin)||0,level:Number(m.level)||1}},ws);return;
    }
    if(m.type==='chat'&&ws.room){broadcast(ws.room,{type:'chat',id:ws.playerId,name:ws.name,text:String(m.text||'').slice(0,200)},ws);}
  });
  ws.on('close',()=>leave(ws));ws.on('error',()=>leave(ws));
});

setInterval(()=>{const now=Date.now();for(const [id,p] of online)if(now-p.lastSeen>30000)online.delete(id)},10000);
server.listen(PORT,()=>console.log(`حرب البيت 3D Online: http://localhost:${PORT}`));
