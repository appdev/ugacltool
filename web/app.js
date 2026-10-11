'use strict';
const api = '/app/ugacltool/api';
const stages = [['prepare','核验硬盘'],['cow','隔离读写验证'],['convert','兼容转换'],['mount','核验原卷'],['native_prepare','备份接管信息'],['release','释放临时访问'],['native_apply','登记存储空间'],['maintain','配置开机维护'],['verify','验证原生读写']];
let csrf = '', selected = null, busy = false, checking = false, isDemo = false;
const byId = id => document.getElementById(id);
function el(tag, text, className) { const node=document.createElement(tag); if(text) node.textContent=text; if(className) node.className=className; return node; }
function error(message) { byId('error').textContent=message; byId('error').hidden=!message; }
async function request(path, body) {
  const options=body ? {method:'POST',headers:{'Content-Type':'application/json','X-Oneclick-CSRF':csrf},body:JSON.stringify(body)} : {};
  const response=await fetch(api+path,options); const data=await response.json();
  if(!response.ok) throw new Error(data.error || '请求未完成'); return data;
}
function capacity(bytes) { const power=bytes>=1024**4?4:bytes>=1024**3?3:2; return (bytes/1024**power).toLocaleString('zh-CN',{maximumFractionDigits:2})+' '+{4:'TiB',3:'GiB',2:'MiB'}[power]; }
function controls() { byId('adopt').disabled=busy || checking || !selected; byId('scan').disabled=busy; for(const input of byId('arrays').querySelectorAll('input')) input.disabled=busy || input.dataset.blocked==='true'; }
async function checkSelection(array,index) {
  const choice=array.selection;selected=choice;checking=true;controls();error('');
  byId('selected').textContent=`已选择阵列 ${index+1}，正在只读核验硬盘身份与系统版本…`;
  try {
    await request('/check',{selection:choice});
    if(selected===choice) {checking=false;byId('selected').textContent=`阵列 ${index+1} 的 ${array.members.length} 块成员盘身份已核验，可开始接管`;controls();}
  } catch(e) {
    if(selected===choice) {selected=null;checking=false;controls();byId('selected').textContent='核验未通过，请重新扫描';error(e.message);}
  }
}
async function scan() {
  selected=null;checking=false;byId('selected').textContent='尚未选择阵列';controls();error('');
  try {
    const data=await request('/arrays'); const area=byId('arrays'); area.replaceChildren();
    if(!data.arrays.length) area.append(el('p','没有发现可识别的绿联阵列。','empty'));
    data.arrays.forEach((array,index)=>{
      const block=el('div',null,'array'), label=el('label'), input=document.createElement('input');
      input.type='radio';input.name='array';input.value=array.selection;input.disabled=!array.eligible;input.dataset.blocked=String(!array.eligible);
      const kind={linear:'JBOD',raid1:'RAID1',raid6:'RAID6'}[array.level] || '未知结构';
      label.append(input,el('span',`阵列 ${index+1} · ${kind} · ${array.members.length} 块成员盘`));block.append(label);
      const scroll=el('div',null,'table-scroll'),table=el('table'),head=el('thead'), row=el('tr');
      ['硬盘序列号','型号','整盘容量'].forEach(text=>row.append(el('th',text)));head.append(row);table.append(head);
      const tbody=el('tbody');array.members.forEach(member=>{
        const r=el('tr'),size=el('td',capacity(member.size));size.append(el('span',member.size.toLocaleString('zh-CN')+' 字节','bytes'));
        r.append(el('td',member.serial,'serial'),el('td',member.model),size);tbody.append(r);
      });table.append(tbody);scroll.append(table);block.append(scroll);
      if(array.reason) block.append(el('p',array.reason,'reason'));
      input.addEventListener('change',()=>checkSelection(array,index));
      area.append(block);
    });controls();
  } catch(e) { error(e.message); }
}
function renderJobs(jobs) {
  const area=byId('jobs');area.replaceChildren();
  if(!jobs.length) {area.append(el('p','选择阵列后，进度会显示在这里。','hint'));return;}
  jobs.slice().reverse().forEach(job=>{
    const block=el('div',null,'job'), heading=el('div',null,'job-heading');
    heading.append(el('h3',job.state==='done' ? `存储空间 ${job.storage_id} · 接管完成` : '阵列接管任务',job.state==='done'?'success':''));
    if(!busy && job.state!=='done') {const resume=el('button','继续核验','secondary');resume.addEventListener('click',()=>start('/resume',{job:job.id}));heading.append(resume);}
    block.append(heading,el('p',job.message,'hint'));
    const list=el('ol',null,'steps');stages.forEach(([key,label])=>list.append(el('li',label,job.completed.includes(key)?'complete':job.stage===key?'current':'')));block.append(list);
    if(job.state==='done') block.append(el('p','原文件已接入飞牛个人文件入口，接下来在飞牛中使用。','hint'));
    area.append(block);
  });
}
async function poll() {
  try {const state=await request('/state');const finished=busy&&!state.running;csrf=state.csrf;busy=state.running;isDemo=state.demo;byId('demo').hidden=!isDemo;renderJobs(state.jobs);controls();if(finished)await scan();}
  catch(e) {error(e.message);}
}
async function start(path,body) {busy=true;controls();error('');try{await request(path,body);await poll();}catch(e){busy=false;controls();error(e.message);}}
byId('scan').addEventListener('click',scan);
byId('adopt').addEventListener('click',()=>{if(selected&&!busy&&!checking)start('/adopt',{selection:selected});});
(async()=>{await poll();await scan();setInterval(poll,1500);})();
